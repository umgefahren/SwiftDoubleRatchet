FROM swift:latest

WORKDIR /app/src/SwiftDoubleRatchet
COPY . .
RUN swift build
RUN swift test
