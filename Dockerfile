# Use Rust base image
FROM rust:latest

# Set the working directory
WORKDIR /app

# Copy the project files into the container
COPY . .

# Build the application
RUN cargo build --release

# Expose the necessary port (e.g., 8080)
EXPOSE 8080

# Run the application
CMD ["./target/release/crawchain"]

