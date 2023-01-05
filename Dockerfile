ARG GOLANG_VERSION=1.19
FROM golang:1.19 as builder

WORKDIR /go/src/github.com/Templum/govulncheck-action/
ENV GO111MODULE=on

COPY go.mod go.sum  ./
RUN go mod download

COPY . .

# Statically compile our app for use in a distroless container
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -v -o action .

FROM golang:$GOLANG_VERSION
ARG VULNCHECK_VERSION=latest 
RUN go install golang.org/x/vuln/cmd/govulncheck@$VULNCHECK_VERSION

ARG GH_PAT_TOKEN
RUN if [[ -n "$GH_PAT_TOKEN" ]]; then echo "No token was provided"; else git config --global --add url."https://govulncheck_action:$GH_PAT_TOKEN@github.com/".insteadOf "https://github.com/"; fi

ARG GOPRIVATE
ENV GOPRIVATE=$GOPRIVATE

COPY --from=builder /go/src/github.com/Templum/govulncheck-action/action /action
ENTRYPOINT ["/action"]