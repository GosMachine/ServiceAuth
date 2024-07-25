docker-push:
	@docker build -t gosmach1ne/gosboostauth .
	@docker push gosmach1ne/gosboostauth:latest