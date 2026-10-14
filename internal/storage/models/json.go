package models

import (
	"database/sql/driver"
	"fmt"
)

// JSON is a GORM-compatible type for storing JSON blobs in both SQLite and
// PostgreSQL. It is a drop-in replacement for gorm.io/datatypes.JSON that
// does not pull in the MySQL driver.
type JSON []byte

// Value implements the driver.Valuer interface, returning the JSON as a string
// so both SQLite (TEXT) and PostgreSQL (JSONB/TEXT) can store it.
func (j JSON) Value() (driver.Value, error) {
	if j == nil {
		return nil, nil
	}
	return string(j), nil
}

// Scan implements the sql.Scanner interface.
func (j *JSON) Scan(value any) error {
	if value == nil {
		*j = nil
		return nil
	}
	switch v := value.(type) {
	case string:
		*j = JSON(v)
	case []byte:
		tmp := make([]byte, len(v))
		copy(tmp, v)
		*j = JSON(tmp)
	default:
		return fmt.Errorf("models.JSON: unsupported scan type %T", value)
	}
	return nil
}

// MarshalJSON implements json.Marshaler so that encoding/json uses the raw
// bytes directly instead of base64-encoding them.
func (j JSON) MarshalJSON() ([]byte, error) {
	if j == nil {
		return []byte("null"), nil
	}
	return j, nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (j *JSON) UnmarshalJSON(data []byte) error {
	tmp := make([]byte, len(data))
	copy(tmp, data)
	*j = JSON(tmp)
	return nil
}
