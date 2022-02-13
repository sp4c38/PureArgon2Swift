.DEFAULT_GOAL := build

build:
	swift build --configuration release
	@mv .build/release/Argon2Executable ./argon2
	@echo "Done"

clean:
	@rm argon2 || true
	@rm -rf .build || true
	@echo "Done"