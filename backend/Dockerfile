FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY SecureScope.Api.csproj ./
RUN dotnet restore SecureScope.Api.csproj

COPY . ./
RUN dotnet publish SecureScope.Api.csproj \
    --configuration Release \
    --no-restore \
    --output /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

RUN mkdir -p /data
COPY --from=build /app/publish ./

EXPOSE 8080
ENTRYPOINT ["dotnet", "SecureScope.Api.dll"]
