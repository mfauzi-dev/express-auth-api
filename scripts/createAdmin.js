import { v4 as uuidv4 } from "uuid";
import bcrypt from "bcrypt";
import sequelize from "../src/config/database.js";
import User from "../src/models/User.js";
import dotenv from "dotenv";
import Role from "../src/models/Role.js";
dotenv.config();

const email = process.env.ADMIN_EMAIL;
const password = process.env.ADMIN_PASSWORD;

const role = await Role.findOne({
    where: {
        name: "admin",
    },
});

const createAdmin = {
    name: "Super Admin",
    email: email,
    password: password,
    role_id: role.id,
    isVerified: true,
};

async function createSuperAdmin() {
    try {
        await sequelize.authenticate();

        const userAlreadyExists = await User.findOne({
            where: {
                email: createAdmin.email,
            },
        });

        if (userAlreadyExists) {
            console.log("Super-admin sudah ada.");
            await sequelize.close();
            return;
        }

        const hashedPassword = await bcrypt.hash(createAdmin.password, 10);

        await User.create({
            name: createAdmin.name,
            email: createAdmin.email,
            password: hashedPassword,
            nomor_induk: createAdmin.nomor_induk,
            roleAs: createAdmin.roleAs,
            isVerified: createAdmin.isVerified,
            createdAt: new Date(),
            updatedAt: new Date(),
        });

        console.log("Super-admin berhasil dibuat!");
        await sequelize.close();
    } catch (error) {
        console.error("Gagal membuat super-admin:", error);
        await sequelize.close();
    }
}

createSuperAdmin();
