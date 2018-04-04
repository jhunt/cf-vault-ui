default:
	./build
	go build ./static/embed
	./embed static/assets.go web
	go build .

demo: default
	./cf-vault-ui
