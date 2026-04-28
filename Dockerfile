FROM eclipse-temurin:17-jdk

WORKDIR /app

COPY . .

RUN chmod +x mvnw
RUN ./mvnw clean package -DskipTests

EXPOSE 9292

CMD ["java", "-jar", "target/security-scanner-0.0.1-SNAPSHOT.jar"]