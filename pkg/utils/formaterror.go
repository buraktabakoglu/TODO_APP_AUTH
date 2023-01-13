package utils

import (
	"errors"
	"strings"
)

func FormatError(errString string) error {

	if strings.Contains(errString, "nickname") {
		return errors.New("already Taken")
	}

	if strings.Contains(errString, "email") {
		return errors.New("email Already Taken")

	}
	if strings.Contains(errString, "hashedPassword") {
		return errors.New("incorrect Password")
	}
	if strings.Contains(errString, "record not found") {
		return errors.New("no Record Found")
	}

	return errors.New("incorrect details")
}
