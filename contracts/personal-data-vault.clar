;; Personal Data Vault Contract
;; Securely stores identity attributes with user control

(define-map user-data
  { owner: principal }
  {
    name: (optional (string-utf8 100)),
    dob: (optional (string-utf8 10)),
    nationality: (optional (string-utf8 50)),
    id-hash: (optional (buff 32)),
    data-hash: (optional (buff 32))
  })

;; Error codes
(define-constant err-unauthorized (err u200))
(define-constant err-invalid-data (err u201))

;; Store or update personal data
(define-public (store-data
                (name (optional (string-utf8 100)))
                (dob (optional (string-utf8 10)))
                (nationality (optional (string-utf8 50)))
                (id-hash (optional (buff 32)))
                (data-hash (optional (buff 32))))
  (begin
    (ok (map-set user-data
                { owner: tx-sender }
                {
                  name: name,
                  dob: dob,
                  nationality: nationality,
                  id-hash: id-hash,
                  data-hash: data-hash
                }))))

;; Get user data (only the owner can access their data)
(define-read-only (get-my-data)
  (default-to
    {
      name: none,
      dob: none,
      nationality: none,
      id-hash: none,
      data-hash: none
    }
    (map-get? user-data { owner: tx-sender })))

;; Check if a user has stored data
(define-read-only (has-data (user principal))
  (is-some (map-get? user-data { owner: user })))

;; Delete personal data
(define-public (delete-my-data)
  (ok (map-delete user-data { owner: tx-sender })))

;; Get data hash for verification (can be accessed by verification contracts)
(define-read-only (get-data-hash (user principal))
  (get data-hash (default-to
    {
      name: none,
      dob: none,
      nationality: none,
      id-hash: none,
      data-hash: none
    }
    (map-get? user-data { owner: user }))))
