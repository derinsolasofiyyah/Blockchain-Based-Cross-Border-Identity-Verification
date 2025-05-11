;; Audit Trail Contract
;; Records history of identity verifications

(define-data-var event-id-counter uint u0)

(define-map audit-events
  { event-id: uint }
  {
    event-type: (string-utf8 20),
    actor: principal,
    subject: principal,
    data-hash: (buff 32),
    timestamp: uint,
    jurisdiction: (optional (string-utf8 10))
  })

;; Error codes
(define-constant err-unauthorized (err u500))

;; Only approved contracts can log events
(define-map approved-contracts principal bool)
(define-data-var admin principal tx-sender)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin)))

;; Set approved contract
(define-public (set-approved-contract (contract principal) (approved bool))
  (begin
    (asserts! (is-admin) err-unauthorized)
    (ok (map-set approved-contracts contract approved))))

;; Log an audit event
(define-public (log-event
                (event-type (string-utf8 20))
                (subject principal)
                (data-hash (buff 32))
                (jurisdiction (optional (string-utf8 10))))
  (let ((new-id (+ (var-get event-id-counter) u1)))
    (asserts! (default-to false (map-get? approved-contracts contract-caller)) err-unauthorized)
    (var-set event-id-counter new-id)
    (ok (map-set audit-events
      { event-id: new-id }
      {
        event-type: event-type,
        actor: tx-sender,
        subject: subject,
        data-hash: data-hash,
        timestamp: block-height,
        jurisdiction: jurisdiction
      }))))

;; Get event details
(define-read-only (get-event (event-id uint))
  (map-get? audit-events { event-id: event-id }))

;; Transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) err-unauthorized)
    (ok (var-set admin new-admin))))
