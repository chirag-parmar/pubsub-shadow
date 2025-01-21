# source: docker.com 
FROM golang:latest

# Set destination for COPY
WORKDIR /app

# # Download Go modules
COPY . .
RUN go mod download;
RUN go build -o node

EXPOSE 7878

# Run
ENTRYPOINT ["./node"]
