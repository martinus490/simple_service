package handler

type RegistrationRequest struct {
	PhoneNumber string `json:"phone_number" validate:"required,numeric,min=10,max=13"`
	Fullname    string `json:"fullname" validate:"required,min=3,max=60"`
	Password    string `json:"password" validate:"required"`
}

type LoginRequest struct {
	PhoneNumber string `json:"phone_number" validate:"required"`
	Password    string `json:"password" validate:"required"`
}

type UpdateMyProfileRequest struct {
	PhoneNumber string `json:"phone_number" validate:"required,numeric,min=10,max=13"`
	FullName    string `json:"fullname" validate:"required,min=3,max=60"`
}
