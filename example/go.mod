module github.com/go-passkeys/go-passkeys/example

go 1.22.0

replace github.com/go-passkeys/go-passkeys v0.0.0 => ../

require (
	github.com/go-passkeys/go-passkeys v0.0.0
	github.com/google/go-cmp v0.6.0
	github.com/mattn/go-sqlite3 v1.14.24
)
