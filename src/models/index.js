import User from "./User.js";
import Role from "./Role.js";

Role.hasMany(User, { foreignKey: "role_id", as: "users" });
User.belongsTo(Role, { foreignKey: "role_id", as: "role" });

export { User, Role };
