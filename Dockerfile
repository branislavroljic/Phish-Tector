FROM openjdk
COPY target/*.jar phishTector.jar
ENTRYPOINT ["java", "-jar", "phishTector.jar"]