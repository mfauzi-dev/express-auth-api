import { DataTypes } from "sequelize";
import sequelize from "../config/database.js";
import User from "./User.js";

const Role = sequelize.define(
    "Role",
    {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        name: {
            type: DataTypes.STRING,
            unique: true,
            allowNull: false,
        },
    },
    {
        tableName: "roles",
        timestamps: true,
        freezeTableName: true,
    }
);

export default Role;
