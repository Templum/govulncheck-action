ARG GOLANG_VERSION=1.19
FROM golang:1.19 as builder

WORKDIR /go/src/github.com/Templum/govulncheck-action/
ENV GO111MODULE=on

ARG PRIVATE_GIT_URL_OVERRIDE
RUN if [[ -z "$PRIVATE_GIT_URL_OVERRIDE" ]] ; then git config --global url.$PRIVATE_GIT_URL_OVERRIDE; else echo "Will not override git config url"; fi

ARG GOPRIVATE

ENV GOPRIVATE=$GOPRIVATE

COPY go.mod go.sum  ./
RUN go mod download

COPY . .

# Statically compile our app for use in a distroless container
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -v -o action .

FROM golang:$GOLANG_VERSION
ARG VULNCHECK_VERSION=latest 
RUN go install golang.org/x/vuln/cmd/govulncheck@$VULNCHECK_VERSION

COPY --from=builder /go/src/github.com/Templum/govulncheck-action/action /action
ENTRYPOINT ["/action"]