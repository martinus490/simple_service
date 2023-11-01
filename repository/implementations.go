package repository

import (
	"context"
)

func (r *Repository) Register(ctx context.Context, user User) (id int64, err error) {
	query := "INSERT INTO user_data (phone_number, fullname, password) VALUES ($1, $2, $3) RETURNING id"
	err = r.Db.QueryRowContext(ctx, query, user.PhoneNumber, user.Fullname, user.Password).Scan(&id)
	if err != nil {
		return
	}
	return
}

func (r *Repository) GetUserByPhoneNumber(ctx context.Context, phoneNumber string) (user User, err error) {
	query := "SELECT id, phone_number, fullname, password, login_counter FROM user_data WHERE phone_number = $1"
	err = r.Db.QueryRowContext(ctx, query, phoneNumber).Scan(&user.Id, &user.PhoneNumber, &user.Fullname, &user.Password, &user.LoginCounter)
	if err != nil {
		return
	}
	return
}

func (r *Repository) IncreaseLoginCounter(ctx context.Context, id int64) (err error) {
	query := "UPDATE user_data SET login_counter = login_counter + 1 WHERE id = $1"
	_, err = r.Db.ExecContext(ctx, query, id)
	if err != nil {
		return
	}
	return
}

func (r *Repository) GetUserById(ctx context.Context, id int64) (user User, err error) {
	query := "SELECT id, phone_number, fullname, password, login_counter FROM user_data WHERE id = $1"
	err = r.Db.QueryRowContext(ctx, query, id).Scan(&user.Id, &user.PhoneNumber, &user.Fullname, &user.Password, &user.LoginCounter)
	if err != nil {
		return
	}
	return
}

func (r *Repository) UpdateUserById(ctx context.Context, user User) (err error) {
	query := "UPDATE user_data SET phone_number = $1, fullname = $2 WHERE id = $3"
	_, err = r.Db.ExecContext(ctx, query, user.PhoneNumber, user.Fullname, user.Id)
	if err != nil {
		return
	}
	return
}
