const databaseName = process.env.MONGO_INITDB_DATABASE || "conshield_events";
const appUser = process.env.CONSHIELD_MONGO_APP_USERNAME;
const appPassword = process.env.CONSHIELD_MONGO_APP_PASSWORD;

if (!appUser || !appPassword) {
  throw new Error("CONSHIELD_MONGO_APP_USERNAME and CONSHIELD_MONGO_APP_PASSWORD are required.");
}

const appDb = db.getSiblingDB(databaseName);
if (!appDb.getUser(appUser)) {
  appDb.createUser({
    user: appUser,
    pwd: appPassword,
    roles: [{ role: "readWrite", db: databaseName }]
  });
}
