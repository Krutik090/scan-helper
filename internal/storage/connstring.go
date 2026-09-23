package storage

import (
	"fmt"

	"go.mongodb.org/mongo-driver/x/mongo/driver/connstring"
)

// connstringDatabase extracts the database name from a MongoDB URI. The
// Go driver requires the database to be selected explicitly, unlike
// Mongoose (which the Node implementation relied on), so the name in the
// URI path is what the configuration means.
func connstringDatabase(uri string) (string, error) {
	cs, err := connstring.ParseAndValidate(uri)
	if err != nil {
		return "", fmt.Errorf("parsing mongo.uri: %w", err)
	}
	return cs.Database, nil
}
