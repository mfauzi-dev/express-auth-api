import sequelize from "../src/config/database.js";
import Role from "../src/models/Role.js";

const seedRoles = async () => {
    try {
        await sequelize.authenticate();

        const roles = ["admin", "user"];

        for (const roleName of roles) {
            const exists = await Role.findOne({
                where: {
                    name: roleName,
                },
            });

            if (!exists) {
                await Role.create({
                    name: roleName,
                    createdAt: new Date(),
                    updatedAt: new Date(),
                });
                console.log(`Role '${roleName}' berhasil ditambahkan`);
            } else {
                console.log(`Role '${roleName}' sudah ada`);
            }
        }
    } catch (error) {
        console.error("Gagal seeding roles:", error);
    } finally {
        await sequelize.close();
    }
};

seedRoles();
