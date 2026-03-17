let userModel = require("../schemas/users");
let bcrypt = require('bcrypt');

module.exports = {
    CreateAnUser: async function (username, password, email, role,
        fullName, avatarUrl, status, loginCount
    ) {
        let newUser = new userModel({
            username: username,
            password: password,
            email: email,
            fullName: fullName,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        })
        await newUser.save();
        return newUser;
    },
    FindUserByUsername: async function (username) {
        return await userModel.findOne({
            isDeleted: false,
            username: username
        })
    },
    CompareLogin: async function (user, password) {
        if (bcrypt.compareSync(password, user.password)) {
            user.loginCount = 0;
            await user.save()
            return user;
        }
        user.loginCount++;
        if (user.loginCount == 3) {
            user.lockTime = new Date(Date.now() + 24 * 60 * 60 * 1000);
            user.loginCount = 0;
        }
        await user.save()
        return false;
    },
    GetUserById: async function (id) {
        try {
            let user = await userModel.findOne({
                _id: id,
                isDeleted: false
            })
            return user;
        } catch (error) {
            return false;
        }
    },
    ChangePassword: async function (userId, oldPassword, newPassword) {
        try {
            // Tìm user
            let user = await userModel.findOne({ _id: userId, isDeleted: false });
            if (!user) {
                throw new Error("Không tìm thấy người dùng");
            }

            // So sánh mật khẩu cũ
            if (!bcrypt.compareSync(oldPassword, user.password)) {
                throw new Error("Mật khẩu cũ không đúng");
            }

            // Validate mật khẩu mới (tối thiểu 8 ký tự, chứa chữ hoa, chữ thường, số)
            const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
            if (!passwordRegex.test(newPassword)) {
                throw new Error("Mật khẩu mới phải tối thiểu 8 ký tự, chứa chữ hoa, chữ thường và số");
            }

            // Kiểm tra mật khẩu mới có giống mật khẩu cũ không
            if (bcrypt.compareSync(newPassword, user.password)) {
                throw new Error("Mật khẩu mới phải khác mật khẩu cũ");
            }

            // Hash mật khẩu mới
            user.password = bcrypt.hashSync(newPassword, 10);
            await user.save();

            return { message: "Đổi mật khẩu thành công" };
        } catch (error) {
            throw new Error(error.message);
        }
    }
}