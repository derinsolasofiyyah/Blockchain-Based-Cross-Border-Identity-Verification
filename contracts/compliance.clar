;; Compliance Contract
;; Ensures adherence to jurisdictional requirements

(define-map jurisdiction-rules
  { jurisdiction-code: (string-utf8 10) }
  {
    min-age: uint,
    required-fields: (list 10 (string-utf8 20)),
    active: bool
  })

(define-map jurisdiction-approvers
  { jurisdiction-code: (string-utf8 10) }
  { approvers: (list 10 principal) })

;; Error codes
(define-constant err-unauthorized (err u400))
(define-constant err-invalid-jurisdiction (err u401))

;; Only admin can manage jurisdictions
(define-data-var admin principal tx-sender)

;; Check if caller is admin
(define-private (is-admin)
  (is-eq tx-sender (var-get admin)))

;; Add or update jurisdiction rules
(define-public (set-jurisdiction-rules
                (jurisdiction-code (string-utf8 10))
                (min-age uint)
                (required-fields (list 10 (string-utf8 20)))
                (active bool))
  (begin
    (asserts! (is-admin) err-unauthorized)
    (ok (map-set jurisdiction-rules
      { jurisdiction-code: jurisdiction-code }
      {
        min-age: min-age,
        required-fields: required-fields,
        active: active
      }))))

;; Set approvers for a jurisdiction
(define-public (set-jurisdiction-approvers
                (jurisdiction-code (string-utf8 10))
                (approvers (list 10 principal)))
  (begin
    (asserts! (is-admin) err-unauthorized)
    (asserts! (is-some (map-get? jurisdiction-rules { jurisdiction-code: jurisdiction-code })) err-invalid-jurisdiction)
    (ok (map-set jurisdiction-approvers
      { jurisdiction-code: jurisdiction-code }
      { approvers: approvers }))))

;; Check if a jurisdiction is active
(define-read-only (is-jurisdiction-active (jurisdiction-code (string-utf8 10)))
  (match (map-get? jurisdiction-rules { jurisdiction-code: jurisdiction-code })
    rules (get active rules)
    false))

;; Get jurisdiction rules
(define-read-only (get-jurisdiction-rules (jurisdiction-code (string-utf8 10)))
  (map-get? jurisdiction-rules { jurisdiction-code: jurisdiction-code }))

;; Check if principal is an approver for a jurisdiction
(define-read-only (is-jurisdiction-approver (jurisdiction-code (string-utf8 10)) (approver principal))
  (match (map-get? jurisdiction-approvers { jurisdiction-code: jurisdiction-code })
    data (is-some (index-of (get approvers data) approver))
    false))

;; Transfer admin rights
(define-public (transfer-admin (new-admin principal))
  (begin
    (asserts! (is-admin) err-unauthorized)
    (ok (var-set admin new-admin))))
