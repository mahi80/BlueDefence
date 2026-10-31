# AEGIS Kafka bridge — build with Maven, run on a JRE.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src ./src
RUN mvn -q -B package

FROM eclipse-temurin:21-jre
RUN useradd --system --uid 10001 bridge && mkdir -p /var/lib/aegis-bridge && chown bridge /var/lib/aegis-bridge
USER bridge
WORKDIR /app
COPY --from=build /src/target/aegis-kafka-bridge.jar /app/aegis-kafka-bridge.jar
VOLUME /var/lib/aegis-bridge
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=70 -XX:+UseG1GC"
ENTRYPOINT ["java", "-jar", "/app/aegis-kafka-bridge.jar"]
