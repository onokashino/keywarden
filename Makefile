# Everything runs in Docker with an 8 GB memory limit and no swap.
# cargo and npm caches live in ~/.cache/keywarden-docker so nothing is downloaded twice.

IMAGE   := keywarden-dev
MEM     := 8g
CACHE   := $(HOME)/.cache/keywarden-docker
# label of check containers: docker ps --filter label=$(LABEL)
LABEL  ?= keywarden-dev=1
DOCKER  = docker run --rm --label $(LABEL) --memory $(MEM) --memory-swap $(MEM) \
          --user "$$(id -u):$$(id -g)" -v "$(CURDIR)":/app -w /app \
          -v $(CACHE)/cargo:/cargo -e CARGO_HOME=/cargo -e CARGO_TARGET_DIR=/app/target \
          -e KEYWARDEN_LANG=ru
CARGO   = $(DOCKER) --name keywarden-$@ -e PATH=/opt/cargo/bin:/usr/bin $(IMAGE) cargo
NODE    = $(DOCKER) --name keywarden-$@ -v $(CACHE)/npm:/npm -e npm_config_cache=/npm -e HOME=/tmp -w /app/extension node:24

.PHONY: image check test clippy build wasm ext ext-firefox clean e2e e2e-crash ui-shots e2e-ext e2e-ssh e2e-secrets check-cross e2e-wine site-shots ui-ssh i18n-new i18n-status

# translation: scaffold a new language (make i18n-new CODE=de NAME=Deutsch) and show progress
i18n-new:
	$(DOCKER) --name keywarden-$@ $(IMAGE) sh scripts/i18n-new.sh "$(CODE)" "$(NAME)"
i18n-status:
	docker run --rm --label $(LABEL) --memory 512m --memory-swap 512m --name keywarden-$@ \
	  --user "$$(id -u):$$(id -g)" -v "$(CURDIR)":/app -w /app python:3.13-slim python scripts/i18n-status.py

# site screenshots: showcase database in two languages -> site/assets/shots and site/assets/shots/ru
site-shots:
	$(CARGO) build -p keywarden-daemon -p keywarden-cli -p keywarden-ui
	$(DOCKER) --name keywarden-site-shots-en -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro -e KEYWARDEN_LANG=en -e SHOWCASE=1 -e DB_NAME=vault -e WORK_TITLE=GitLab \
	  -e SHOTS=target/showcase-en $(IMAGE) sh scripts/ui-harness.sh scripts/ui-showcase.scenario
	$(DOCKER) --name keywarden-site-shots-ru -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro -e KEYWARDEN_LANG=ru -e SHOWCASE=1 -e DB_NAME=пароли -e WORK_TITLE=GitLab \
	  -e SHOTS=target/showcase-ru $(IMAGE) sh scripts/ui-harness.sh scripts/ui-showcase.scenario
	docker run --rm --label $(LABEL) --memory 1g --memory-swap 1g --name keywarden-site-webp \
	  --user "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$(CURDIR)":/app -w /app python:3.13-slim \
	  sh -c "pip install -q --user pillow 2>/dev/null && python scripts/site-shots.py"

image:
	mkdir -p $(CACHE)/cargo $(CACHE)/npm
	docker build -t $(IMAGE) -f docker/Dockerfile.dev docker

check: ; $(CARGO) check --workspace --all-targets
test:  ; $(CARGO) test --workspace
clippy:; $(CARGO) clippy --workspace --all-targets -- -D warnings
build: ; $(CARGO) build --workspace --release

# Rust -> WASM -> extension/wasm (imported by background.ts)
wasm:
	$(DOCKER) --name keywarden-wasm -e PATH=/opt/cargo/bin:/usr/bin $(IMAGE) sh scripts/build-wasm.sh

ext: wasm
	$(NODE) sh -c "npm install && npm run build"
ext-firefox: wasm
	$(NODE) sh -c "npm install && npm run build:firefox"

clean:
	rm -rf target extension/.output extension/.wxt extension/wasm

# daemon + kw on a KeePassXC database, result checked with keepassxc-cli
e2e:
	$(CARGO) build -p keywarden-daemon -p keywarden-cli
	$(DOCKER) --name keywarden-e2e $(IMAGE) sh scripts/e2e-cli.sh

e2e-crash:
	$(CARGO) build -p keywarden-daemon -p keywarden-cli
	$(DOCKER) --name keywarden-e2e-crash $(IMAGE) sh scripts/e2e-crash-clipboard.sh

# UI in headless sway with software Vulkan; screenshots in target/shots
# Windows and macOS from Linux: clippy (no linking; the macOS UI cannot be checked this way, see .github)
check-cross:
	$(DOCKER) --name keywarden-$@ -e HOME=/tmp -e CC_aarch64_apple_darwin=zigcc-macos \
	  -e PATH=/opt/cargo/bin:/usr/bin:/usr/local/bin $(IMAGE) sh -c '\
	  for t in x86_64-pc-windows-gnu aarch64-apple-darwin; do \
	    cargo clippy -q --target $$t -p keywarden-core -p keywarden-daemon -p keywarden-cli \
	      -p keywarden-host --all-targets -- -D warnings || exit 1; done; \
	  cargo clippy -q --target x86_64-pc-windows-gnu -p keywarden-ui --all-targets -- -D warnings'

# daemon and kw for Windows under Wine: named pipe, unlock, write, lock
e2e-wine:
	$(CARGO) build -q --release --target x86_64-pc-windows-gnu -p keywarden-daemon -p keywarden-cli
	docker build -q -t keywarden-wine -f docker/Dockerfile.wine docker
	mkdir -p target/wine && rm -f target/wine/test.kdbx
	$(DOCKER) --name keywarden-$@-db $(IMAGE) sh -c "printf 'pw\\npw\\n' | keepassxc-cli db-create -p target/wine/test.kdbx >/dev/null && printf 'pw\\n' | keepassxc-cli add -u octo target/wine/test.kdbx GitHub -g >/dev/null"
	$(DOCKER) --name keywarden-$@ keywarden-wine sh scripts/e2e-wine.sh

# SSH in the window: unlock on an ssh request, connect from the launcher (a stub terminal writes
# the command to a file), the whole settings tab, the new key window (create and add by keyboard)
ui-ssh:
	$(CARGO) build -p keywarden-daemon -p keywarden-cli -p keywarden-ui
	awk -F: -v OFS=: -v u=$$(id -u) '$$3 == u { $$7 = "/bin/sh" } 1' /etc/passwd > $(CACHE)/passwd-sh
	$(DOCKER) --name keywarden-ui-ssh -v $(CACHE)/passwd-sh:/etc/passwd:ro -v /etc/group:/etc/group:ro \
	  -e 'EXTRA_CONFIG=terminal = ["sh", "-c", "echo \"$$*\" > /tmp/kw-ssh-called", "term"]' \
	  $(IMAGE) sh scripts/ui-harness.sh scripts/ui-ssh.scenario
	$(DOCKER) --name keywarden-ui-ssh -v $(CACHE)/passwd-sh:/etc/passwd:ro -v /etc/group:/etc/group:ro \
	  -e RES=1280x1500 $(IMAGE) sh scripts/ui-harness.sh scripts/ui-ssh-settings.scenario
	$(DOCKER) --name keywarden-ui-ssh -v $(CACHE)/passwd-sh:/etc/passwd:ro -v /etc/group:/etc/group:ro \
	  $(IMAGE) sh scripts/ui-harness.sh scripts/ui-ssh-new.scenario
	$(DOCKER) --name keywarden-ui-ssh -v $(CACHE)/passwd-sh:/etc/passwd:ro -v /etc/group:/etc/group:ro \
	  $(IMAGE) sh scripts/ui-harness.sh scripts/ui-ssh-host.scenario

ui-shots:
	$(CARGO) build -p keywarden-daemon -p keywarden-cli -p keywarden-ui
	$(DOCKER) --name keywarden-ui-shots $(IMAGE) sh scripts/ui-harness.sh scripts/ui-launcher.scenario
	$(DOCKER) --name keywarden-ui-shots $(IMAGE) sh scripts/ui-harness.sh scripts/ui-main.scenario
	$(DOCKER) --name keywarden-ui-shots $(IMAGE) sh scripts/ui-harness.sh scripts/ui-attach.scenario
	$(DOCKER) --name keywarden-ui-shots $(IMAGE) sh scripts/ui-harness.sh scripts/ui-confirm.scenario
	$(DOCKER) --name keywarden-ui-shots $(IMAGE) sh scripts/ui-harness.sh scripts/ui-pin.scenario
	$(DOCKER) --name keywarden-ui-shots $(IMAGE) sh scripts/ui-harness.sh scripts/ui-wallet.scenario
	$(DOCKER) --name keywarden-ui-shots $(IMAGE) sh scripts/ui-harness.sh scripts/ui-sync.scenario
	$(DOCKER) --name keywarden-ui-shots $(IMAGE) sh scripts/ui-harness.sh scripts/ui-settings.scenario

e2e-ext: ext
	$(CARGO) build -p keywarden-daemon -p keywarden-cli -p keywarden-host
	$(DOCKER) --name keywarden-e2e-ext -v $(CACHE)/npm:/npm -e npm_config_cache=/npm $(IMAGE) sh scripts/e2e-ext.sh

e2e-ssh:
	$(CARGO) build -p keywarden-daemon -p keywarden-cli
	# ssh-keygen and ssh-add need the uid in /etc/passwd; sshd in the test also needs an existing
	# shell, which the host user may lack in the image: a copy with /bin/sh
	awk -F: -v OFS=: -v u=$$(id -u) '$$3 == u { $$7 = "/bin/sh" } 1' /etc/passwd > $(CACHE)/passwd-sh
	$(DOCKER) --name keywarden-e2e-ssh -v $(CACHE)/passwd-sh:/etc/passwd:ro -v /etc/group:/etc/group:ro $(IMAGE) sh scripts/e2e-ssh.sh

e2e-secrets:
	$(CARGO) build -p keywarden-daemon -p keywarden-cli
	$(DOCKER) --name keywarden-e2e-secrets -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro $(IMAGE) sh scripts/e2e-secrets.sh
