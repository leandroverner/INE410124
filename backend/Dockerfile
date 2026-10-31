# --- build ---
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /build
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B -DskipTests package && mv target/prontuarios-*.jar target/app.jar

# --- runtime ---
FROM eclipse-temurin:25-jre
RUN useradd --system --uid 1001 app && mkdir -p /data/keys && chown app /data/keys
USER app
WORKDIR /app
COPY --from=build /build/target/app.jar app.jar
ENV SERVER_KEY_FILE=/data/keys/servidor-ec-p256.jwk
VOLUME /data/keys
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]
