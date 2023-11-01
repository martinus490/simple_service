// This file contains types that are used in the repository layer.
package repository

type User struct {
	Id           int64
	PhoneNumber  string
	Fullname     string
	Password     string
	LoginCounter int64
}
