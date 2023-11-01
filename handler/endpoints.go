package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/SawitProRecruitment/UserService/generated"
	model "github.com/SawitProRecruitment/UserService/repository"
	"github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret = []byte("MySecretKey")

func (s *Server) Register(ctx echo.Context) error {

	var resp generated.ErrorResponse
	var req RegistrationRequest
	err := json.NewDecoder(ctx.Request().Body).Decode(&req)
	if err != nil {
		log.Println("[Register] failed to decode request body", err)
		return err
	}

	if err = s.Validator.Struct(req); err != nil {
		resp.Message = err.Error()
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	user := model.User{
		PhoneNumber: req.PhoneNumber,
		Fullname:    req.Fullname,
		Password:    req.Password,
	}

	if err = validateRegister(user); err != nil {
		resp.Message = err.Error()
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	hashedPass, err := hashPassword(user.Password)
	if err != nil {
		log.Println("[Register] failed to generate hashed password")
		return ctx.JSON(http.StatusInternalServerError, err)
	}

	user.Password = hashedPass

	log.Println(user.Password)
	userId, err := s.Repository.Register(context.Background(), user)
	if err != nil {
		log.Println("[Register] failed to register user", err)
		return ctx.JSON(http.StatusInternalServerError, err)
	}

	okResp := generated.RegistrationResponse{
		Id: &userId,
	}
	return ctx.JSON(http.StatusOK, okResp)
}

func (s *Server) Login(ctx echo.Context) error {

	var resp generated.ErrorResponse
	var req LoginRequest
	err := json.NewDecoder(ctx.Request().Body).Decode(&req)
	if err != nil {
		log.Println("[Login] failed to decode request body", err)
		return err
	}

	if err = s.Validator.Struct(req); err != nil {
		resp.Message = err.Error()
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	user, err := s.Repository.GetUserByPhoneNumber(context.Background(), req.PhoneNumber)
	if err != nil {
		log.Println("[Login] failed to get user by phone numer", req.PhoneNumber, err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if match := checkPassword(req.Password, user.Password); !match {
		log.Println("[Login] wrong password", match)
		resp.Message = "Wrong Password"
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	err = s.Repository.IncreaseLoginCounter(context.Background(), user.Id)
	if err != nil {
		log.Println("[Login] failed to increase login counter", err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	jwt, err := generateJWT(fmt.Sprint(user.Id))
	if err != nil {
		log.Println("[Login] failed to generate JWT", err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	okResp := generated.LoginResponse{
		Id:  &user.Id,
		Jwt: &jwt,
	}
	return ctx.JSON(http.StatusOK, okResp)
}

func (s *Server) GetMyProfile(ctx echo.Context, params generated.GetMyProfileParams) error {

	var resp generated.ErrorResponse
	claims, err := validateJWT(params.Jwt)
	if err != nil {
		log.Println("[GetMyProfile] invalid JWT", err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusForbidden, resp)
	}

	userId := claims["user_id"].(string)
	userIdInt, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		resp.Message = err.Error()
		return ctx.JSON(http.StatusForbidden, resp)
	}

	user, err := s.Repository.GetUserById(context.Background(), userIdInt)
	if err != nil {
		log.Println("[GetMyProfile] failed to get  by id", userId, err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusForbidden, resp)
	}

	okResp := generated.GetMyProfileResponse{
		Name:        &user.Fullname,
		PhoneNumber: &user.PhoneNumber,
	}
	return ctx.JSON(http.StatusOK, okResp)
}

func (s *Server) UpdateMyProfile(ctx echo.Context, params generated.UpdateMyProfileParams) error {

	ctxBackgroud := context.Background()
	var resp generated.ErrorResponse
	claims, err := validateJWT(params.Jwt)
	if err != nil {
		log.Println("[UpdateMyProfile] invalid JWT", err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusForbidden, resp)
	}

	var req UpdateMyProfileRequest
	err = json.NewDecoder(ctx.Request().Body).Decode(&req)
	if err != nil {
		log.Println("[UpdateMyProfile] failed to decode request body", err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	if err = s.Validator.Struct(req); err != nil {
		log.Println("[UpdateMyProfile] failed to validate request body", err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusBadRequest, resp)
	}

	userId := claims["user_id"].(string)
	userIdInt, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		log.Println("[UpdateMyProfile] failed to convert user_id", err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	existingUser, err := s.Repository.GetUserByPhoneNumber(ctxBackgroud, req.PhoneNumber)
	if err != nil && err != sql.ErrNoRows {
		log.Println("[UpdateMyProfile] failed to get existing user", err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	if existingUser.Id != 0 && existingUser.Id != userIdInt {
		resp.Message = "Phone number already used"
		return ctx.JSON(http.StatusConflict, resp)
	}

	userUpdate := model.User{
		Id:          userIdInt,
		PhoneNumber: req.PhoneNumber,
		Fullname:    req.FullName,
	}

	err = s.Repository.UpdateUserById(ctxBackgroud, userUpdate)
	if err != nil {
		log.Println("[UpdateMyProfile] failed to update existing user", err)
		resp.Message = err.Error()
		return ctx.JSON(http.StatusInternalServerError, resp)
	}

	okResp := generated.ErrorResponse{
		Message: "success",
	}
	return ctx.JSON(http.StatusOK, okResp)
}

func validateRegister(user model.User) error {
	if !strings.HasPrefix(user.PhoneNumber, "+62") {
		return errors.New("phone number must start with '+62'")
	}

	uppercaseRegex := regexp.MustCompile(`[A-Z]`)
	numberRegex := regexp.MustCompile(`[0-9]`)
	specialCharRegex := regexp.MustCompile(`[^A-Za-z0-9]`)
	if !uppercaseRegex.MatchString(user.Password) ||
		!numberRegex.MatchString(user.Password) ||
		!specialCharRegex.MatchString(user.Password) {
		return errors.New("password must containing at least 1 capital characters and 1 number and 1 special (nonalpha-numeric) characters")
	}

	return nil
}

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func checkPassword(password, hashedPassword string) bool {
	log.Println(hashedPassword, password)
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func generateJWT(userID string) (string, error) {
	// to use RS256, needs to change here and generate RSA key using openssl and then change jwtSecret using the private key
	// have some issue in generating encoded RSA private key
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix() // Token expires in 24 hours

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func validateJWT(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
