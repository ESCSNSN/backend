FROM openjdk:17
WORKDIR /app
COPY build/libs/esclogin-1.0.jar app.jar
LABEL authors="JANG"
EXPOSE 8081
ENTRYPOINT ["java", "-jar", "app.jar"]



