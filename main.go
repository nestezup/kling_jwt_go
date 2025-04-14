package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func encodeJwtToken(ak, sk string) (string, error) {
	// JWT 헤더 설정
	headers := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}

	// 현재 시간 구하기
	now := time.Now()

	// JWT 페이로드 설정
	payload := jwt.MapClaims{
		"iss": ak,                         // 발급자(Issuer): 액세스 키
		"exp": now.Unix() + 1800,          // 만료 시간(Expiry): 현재 시간 + 1800초(30분)
		"nbf": now.Unix() - 5,             // 유효 시작 시간(Not Before): 현재 시간 - 5초
	}

	// 토큰 생성기 초기화 (헤더 포함)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	
	// 헤더 설정
	for k, v := range headers {
		token.Header[k] = v
	}

	// 토큰 서명하여 최종 문자열 생성
	tokenString, err := token.SignedString([]byte(sk))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func main() {
	// 액세스 키와 시크릿 키 설정
	ak := "65994bb7380c4d4fb8f1fae2beb6c4f5"
	sk := "6a5f57c6ae3746988d3a66173cbf749e"

	// JWT 토큰 생성 엔드포인트
	http.HandleFunc("/generate-token", func(w http.ResponseWriter, r *http.Request) {
		// CORS 헤더 설정
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// OPTIONS 요청 처리
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// JWT 토큰 생성
		token, err := encodeJwtToken(ak, sk)
		if err != nil {
			http.Error(w, fmt.Sprintf("토큰 생성 오류: %v", err), http.StatusInternalServerError)
			return
		}

		// 응답 데이터 생성
		response := map[string]interface{}{
			"token":      token,
			"expires_in": 1800,
		}

		// JSON 응답
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	})

	// 서버 시작
	log.Println("서버 시작: 18080 포트")
	if err := http.ListenAndServe(":18080", nil); err != nil {
		log.Fatal("서버 시작 실패:", err)
	}
}