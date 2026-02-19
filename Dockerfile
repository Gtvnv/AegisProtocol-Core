# 1. Build Stage (Compila o projeto usando Maven e Java 21)
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
# O comando -DskipTests evita rodar os testes de novo no build (já rodamos na IDE)
RUN mvn clean package -DskipTests

# 2. Run Stage (Imagem leve apenas para rodar o JAR)
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Cria usuário não-root por segurança (Best Practice de Container)
RUN addgroup -S aegis && adduser -S aegis -G aegis
USER aegis:aegis

# Copia o JAR gerado no passo anterior
COPY --from=build /app/target/aegis-core-0.0.1-SNAPSHOT.jar app.jar

# Copia a pasta de chaves (O container precisa delas para assinar!)
# Nota: Em produção real, usaríamos Volumes ou Secrets, mas para MVP copiamos.
COPY keys ./keys

# Expõe a porta que definimos no application.yml
EXPOSE 9090

# Comando de inicialização
ENTRYPOINT ["java", "-jar", "app.jar"]