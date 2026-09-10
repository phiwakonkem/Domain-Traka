package handlers

import (
	"log"
	"net/http"
)

func respondError(w http.ResponseWriter, context string, err error, clientMessage string, statusCode int) {
	log.Printf("ERROR [%s]: %v", context, err)
	http.Error(w, clientMessage, statusCode)
}