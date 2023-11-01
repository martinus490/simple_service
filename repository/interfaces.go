// This file contains the interfaces for the repository layer.
// The repository layer is responsible for interacting with the database.
// For testing purpose we will generate mock implementations of these
// interfaces using mockgen. See the Makefile for more information.
package repository

import "context"

type RepositoryInterface interface {
	Register(ctx context.Context, user User) (id int64, err error)
	GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (user User, err error)
	IncreaseLoginCounter(ctx context.Context, id int64) (err error)
	GetUserById(ctx context.Context, id int64) (user User, err error)
	UpdateUserById(ctx context.Context, user User) (err error)
}
