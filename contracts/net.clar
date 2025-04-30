;; SecureNet Smart Contract

;; Error codes
(define-constant ERR_NO_PERMISSION (err u100))
(define-constant ERR_URL_EXISTS (err u101))
(define-constant ERR_URL_NOT_REGISTERED (err u102))
(define-constant ERR_SYSTEM_PAUSED (err u103))
(define-constant ERR_BOND_TOO_LOW (err u104))
(define-constant ERR_TIMEOUT_ACTIVE (err u105))
(define-constant ERR_LIMIT_EXCEEDED (err u106))
(define-constant ERR_TIME_CONSTRAINT (err u107))
(define-constant ERR_BAD_URL_FORMAT (err u400))
(define-constant ERR_BAD_CERT_FORMAT (err u401))
(define-constant ERR_WEAK_EVIDENCE (err u402))
(define-constant ERR_BAD_THREAT_LEVEL (err u403))
(define-constant ERR_BAD_SHIELD_LEVEL (err u404))
(define-constant ERR_INVALID_OWNER (err u405))

;; System constants
(define-constant TIMEOUT_PERIOD_SECONDS u86400) ;; 24 hours in seconds
(define-constant MIN_BOND_AMOUNT u1000000) ;; in microSTX
(define-constant MIN_SENTINEL_RATING u50)
(define-constant MAX_EVIDENCE_LENGTH u500)

;; Input validation functions
(define-private (validate-url-format (url (string-ascii 255)))
    (begin
        (asserts! (>= (len url) u3) (err "URL too short"))
        (asserts! (<= (len url) u255) (err "URL too long"))
        (asserts! (is-eq (index-of url ".") none) (err "Invalid character: ."))
        (asserts! (is-eq (index-of url "/") none) (err "Invalid character: /"))
        (asserts! (is-eq (index-of url " ") none) (err "Invalid character: space"))
        (ok true)))

(define-private (validate-cert-format (cert (string-ascii 50)))
    (begin
        (asserts! (>= (len cert) u5) (err "Certificate too short"))
        (asserts! (<= (len cert) u50) (err "Certificate too long"))
        (asserts! (is-eq (index-of cert "<") none) (err "Invalid character: <"))
        (asserts! (is-eq (index-of cert ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-evidence-format (evidence (string-ascii 500)))
    (begin
        (asserts! (>= (len evidence) u10) (err "Evidence too short"))
        (asserts! (<= (len evidence) u500) (err "Evidence too long"))
        (asserts! (is-eq (index-of evidence "<") none) (err "Invalid character: <"))
        (asserts! (is-eq (index-of evidence ">") none) (err "Invalid character: >"))
        (ok true)))

(define-private (validate-threat-level (level uint))
    (begin
        (asserts! (>= level u1) (err "Threat level too low"))
        (asserts! (<= level u100) (err "Threat level too high"))
        (ok true)))

(define-private (validate-shield-level (level uint))
    (begin
        (asserts! (>= level u1) (err "Shield level too low"))
        (asserts! (<= level u10) (err "Shield level too high"))
        (ok true)))

;; Administrative state variables
(define-data-var system_admin principal tx-sender)
(define-data-var url_registration_fee uint u100)
(define-data-var required_confirmations uint u5)
(define-data-var system_shield_level uint u1)
(define-data-var system_paused bool false)

;; Primary data structures
(define-map protected_urls
    {url: (string-ascii 255)}
    {
        url_owner: principal,
        shield_level: (string-ascii 20),
        registration_time: uint,
        threat_score: uint,
        total_incidents: uint,
        bond_amount: uint,
        last_scan_time: uint,
        security_cert: (string-ascii 50)
    })

(define-map threat_reports
    {url: (string-ascii 255)}
    {
        reporter: principal,
        report_time: uint,
        evidence: (string-ascii 500),
        status: (string-ascii 20),
        severity: uint,
        affected_users: uint
    })

(define-map sentinel_performance
    {sentinel_id: principal, watched_url: (string-ascii 255)}
    {
        reports_filed: uint,
        last_report_time: uint,
        reputation: uint,
        bond_amount: uint,
        confirmed_reports: uint
    })

(define-map url_scan_history
    {url: (string-ascii 255)}
    {
        scan_frequency: uint,
        last_scan_time: uint,
        scanner_id: principal,
        scan_score: uint,
        scan_status: (string-ascii 50)
    })

(define-map sentinel_profile
    {sentinel_id: principal}
    {
        bond_amount: uint,
        completed_reviews: uint,
        trust_score: uint,
        last_active_time: uint,
        status: (string-ascii 20)
    })

;; Query functions
(define-read-only (get-url-security-info (url (string-ascii 255)))
    (match (map-get? protected_urls {url: url})
        url_data (ok url_data)
        (err ERR_URL_NOT_REGISTERED)))

(define-read-only (has-reported-threats (url (string-ascii 255)))
    (is-some (map-get? threat_reports {url: url})))

(define-read-only (get-sentinel-rating (sentinel_id principal))
    (match (map-get? sentinel_performance {sentinel_id: sentinel_id, watched_url: ""})
        sentinel_data (get reputation sentinel_data)
        u0))

;; Core operations
(define-public (register-protected-url 
    (url (string-ascii 255))
    (security_cert (string-ascii 50)))
    (let (
        (current_time (unwrap-panic (get-block-info? time (- block-height u1))))
        (required_bond (* MIN_BOND_AMOUNT (var-get system_shield_level))))
        
        ;; Input validation
        (asserts! (is-ok (validate-url-format url)) ERR_BAD_URL_FORMAT)
        (asserts! (is-ok (validate-cert-format security_cert)) ERR_BAD_CERT_FORMAT)
        (asserts! (is-eq tx-sender (var-get system_admin)) ERR_NO_PERMISSION)
        (asserts! (>= (stx-get-balance tx-sender) required_bond) ERR_BOND_TOO_LOW)
        
        (match (map-get? protected_urls {url: url})
            existing_url ERR_URL_EXISTS
            (begin
                (try! (stx-transfer? required_bond tx-sender (as-contract tx-sender)))
                (map-set protected_urls
                    {url: url}
                    {
                        url_owner: tx-sender,
                        shield_level: "verified",
                        registration_time: current_time,
                        threat_score: u0,
                        total_incidents: u0,
                        bond_amount: required_bond,
                        last_scan_time: current_time,
                        security_cert: security_cert
                    })
                (ok true)))))

(define-public (report-threat 
    (url (string-ascii 255)) 
    (evidence (string-ascii 500))
    (threat_level uint))
    (let (
        (current_time (unwrap-panic (get-block-info? time (- block-height u1))))
        (sentinel_data (default-to 
            {reports_filed: u0, last_report_time: u0, reputation: u0, bond_amount: u0, confirmed_reports: u0}
            (map-get? sentinel_performance {sentinel_id: tx-sender, watched_url: url}))))
        
        ;; Input validation
        (asserts! (is-ok (validate-url-format url)) ERR_BAD_URL_FORMAT)
        (asserts! (is-ok (validate-evidence-format evidence)) ERR_WEAK_EVIDENCE)
        (asserts! (is-ok (validate-threat-level threat_level)) ERR_BAD_THREAT_LEVEL)
        (asserts! (not (var-get system_paused)) ERR_SYSTEM_PAUSED)
        (asserts! (>= (get reputation sentinel_data) MIN_SENTINEL_RATING) ERR_BOND_TOO_LOW)
        (asserts! (> (- current_time (get last_report_time sentinel_data)) TIMEOUT_PERIOD_SECONDS) ERR_TIMEOUT_ACTIVE)
        
        (map-set threat_reports
            {url: url}
            {
                reporter: tx-sender,
                report_time: current_time,
                evidence: evidence,
                status: "pending",
                severity: threat_level,
                affected_users: u1
            })
        
        (map-set sentinel_performance
            {sentinel_id: tx-sender, watched_url: url}
            {
                reports_filed: (+ (get reports_filed sentinel_data) u1),
                last_report_time: current_time,
                reputation: (+ (get reputation sentinel_data) u5),
                bond_amount: (get bond_amount sentinel_data),
                confirmed_reports: (get confirmed_reports sentinel_data)
            })
        (ok true)))

(define-private (update-url-threat-score (url (string-ascii 255)) (score_change int))
    (begin 
        (asserts! (is-ok (validate-url-format url)) ERR_BAD_URL_FORMAT)
        (match (map-get? protected_urls {url: url})
            url_data 
                (begin
                    (map-set protected_urls
                        {url: url}
                        (merge url_data {
                            threat_score: (+ (get threat_score url_data) 
                                (if (> score_change 0) 
                                    (to-uint score_change)
                                    u0))
                        }))
                    (ok true))
            ERR_URL_NOT_REGISTERED)))

(define-public (verify-threat-report 
    (url (string-ascii 255))
    (is_confirmed bool))
    (let (
        (current_time (unwrap-panic (get-block-info? time (- block-height u1))))
        (sentinel_data (unwrap! (map-get? sentinel_profile {sentinel_id: tx-sender}) ERR_NO_PERMISSION)))
        
        (asserts! (is-ok (validate-url-format url)) ERR_BAD_URL_FORMAT)
        (asserts! (>= (get bond_amount sentinel_data) MIN_BOND_AMOUNT) ERR_BOND_TOO_LOW)
        
        (map-set sentinel_profile
            {sentinel_id: tx-sender}
            (merge sentinel_data {
                completed_reviews: (+ (get completed_reviews sentinel_data) u1),
                last_active_time: current_time
            }))
        (if is_confirmed
            (update-url-threat-score url 10)
            (update-url-threat-score url -5))))

(define-public (register-as-sentinel (bond_amount uint))
    (let (
        (current_time (unwrap-panic (get-block-info? time (- block-height u1)))))
        (asserts! (>= bond_amount MIN_BOND_AMOUNT) ERR_BOND_TOO_LOW)
        (asserts! (>= (stx-get-balance tx-sender) bond_amount) ERR_BOND_TOO_LOW)
        
        (map-set sentinel_profile
            {sentinel_id: tx-sender}
            {
                bond_amount: bond_amount,
                completed_reviews: u0,
                trust_score: u100,
                last_active_time: current_time,
                status: "active"
            })
        (unwrap! (stx-transfer? bond_amount tx-sender (as-contract tx-sender))
                 ERR_BOND_TOO_LOW)
        (ok true)))

;; System management functions
(define-public (update-shield-level (new_level uint))
    (begin
        (asserts! (is-ok (validate-shield-level new_level)) ERR_BAD_SHIELD_LEVEL)
        (asserts! (is-eq tx-sender (var-get system_admin)) ERR_NO_PERMISSION)
        (var-set system_shield_level new_level)
        (ok true)))

(define-public (set-system-pause (pause_state bool))
    (begin
        (asserts! (is-eq tx-sender (var-get system_admin)) ERR_NO_PERMISSION)
        (var-set system_paused pause_state)
        (ok true)))

(define-public (transfer-system-ownership (new_owner principal))
    (begin
        (asserts! (is-eq tx-sender (var-get system_admin)) ERR_NO_PERMISSION)
        (asserts! (not (is-eq new_owner 'SP000000000000000000002Q6VF78)) ERR_INVALID_OWNER)
        (var-set system_admin new_owner)
        (ok true)))

;; System initialization
(define-public (initialize-system (admin_address principal))
    (begin
        (asserts! (is-eq tx-sender (var-get system_admin)) ERR_NO_PERMISSION)
        (asserts! (not (is-eq admin_address 'SP000000000000000000002Q6VF78)) ERR_INVALID_OWNER)
        (var-set system_admin admin_address)
        (var-set system_shield_level u1)
        (var-set system_paused false)
        (ok true)))