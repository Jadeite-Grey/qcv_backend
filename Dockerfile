FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Build tools for liboqs, plus WeasyPrint runtime libraries (PDF report generation)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git cmake libssl-dev \
    python3 python3-venv python3-pip python3-dev \
    libpq-dev \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs (the C library QCV's crypto depends on)
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs
RUN cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON && \
    cmake --build liboqs/build --parallel 4 && \
    cmake --build liboqs/build --target install

ENV LD_LIBRARY_PATH=/usr/local/lib

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

RUN chmod +x start.sh

EXPOSE 8000

CMD ["./start.sh"]
