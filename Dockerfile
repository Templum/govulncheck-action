ARG GOLANG_VERSION=1.21
# This golang version is for the builder only
FROM golang:1.24 as builder

WORKDIR /go/src/github.com/Templum/govulncheck-action/
ENV GO111MODULE=on

COPY go.mod go.sum  ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-w -s" -v -o action .
# This golang version determines in which golang environment the customer code is checked
FROM golang:$GOLANG_VERSION
ARG VULNCHECK_VERSION=v1.0.0 
RUN go install golang.org/x/vuln/cmd/govulncheck@$VULNCHECK_VERSION

# This allows private repositories hosted on Github
ARG GH_PAT_TOKEN
RUN if [[ -n "$GH_PAT_TOKEN" ]]; then echo "No token was provided"; else git config --global --add url."https://govulncheck_action:$GH_PAT_TOKEN@github.com/".insteadOf "https://github.com/"; fi
ARG GOPRIVATE
ENV GOPRIVATE=$GOPRIVATE

COPY --from=builder /go/src/github.com/Templum/govulncheck-action/action /action
ENTRYPOINT ["/action"]