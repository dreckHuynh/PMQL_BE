const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const { connectDB, sequelize } = require("./config/database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

// API Đăng nhập
app.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Truy vấn user bằng Raw Query
    const user = await sequelize.query(
      `SELECT * FROM "User" WHERE username = :username LIMIT 1;`,
      {
        replacements: { username },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!user || user.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const existingUser = user[0];

    // Kiểm tra mật khẩu
    const isMatch = await bcrypt.compare(password, existingUser.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // Tạo JWT token
    const token = jwt.sign(
      {
        ...existingUser,
        id: existingUser.id.toString(),
        updated_by: existingUser.updated_by?.toString(),
        created_by: existingUser.created_by?.toString(),
      },
      process.env.JWT_SECRET || "your_secret_key",
      { expiresIn: "24h" }
    );

    // Thiết lập cookie
    res.cookie("token", token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    return res.json({
      message: "Logged in successfully",
      data: {
        token,
        is_first_login: existingUser.is_first_login,
      },
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ error: "Login failed" });
  }
});

//Logout

app.post("/auth/logout", (req, res) => {
  res.cookie("token", "", {
    expires: new Date(0),
    path: "/",
  });

  return res.json({ message: "Logged out" });
});

// Update password

app.put("/auth/update-password", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Tìm user trong database bằng raw query
    const user = await sequelize.query(
      `SELECT * FROM "User" WHERE username = :username LIMIT 1;`,
      {
        replacements: { username },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!user || user.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const existingUser = user[0];

    // Hash mật khẩu mới
    const hashedPassword = await bcrypt.hash(password, 10);

    // Cập nhật mật khẩu trong database
    await sequelize.query(
      `UPDATE "User" SET password = :hashedPassword, is_first_login = false WHERE username = :username;`,
      {
        replacements: { hashedPassword, username },
        type: sequelize.QueryTypes.UPDATE,
      }
    );

    const token = jwt.sign(
      {
        ...existingUser,
        id: existingUser.id.toString(),
        updated_by: existingUser.updated_by?.toString(),
        created_by: existingUser.created_by?.toString(),
      },
      process.env.JWT_SECRET || "your_secret_key",
      { expiresIn: "24h" }
    );

    // Cập nhật cookie mới
    res.cookie("token", token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Error updating password:", err);
    return res.status(500).json({ error: "Failed to update password" });
  }
});

app.post("/auth/update-password", async (req, res) => {
  try {
    const { username, password, newPassword } = req.body;

    // Tìm user trong database bằng raw query
    const user = await sequelize.query(
      `SELECT * FROM "User" WHERE username = :username LIMIT 1;`,
      {
        replacements: { username },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!user || user.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const existingUser = user[0];

    // Hash mật khẩu mới
    const hashedPassword = await bcrypt.hash(password, 10);
    const newHashedPassword = await bcrypt.hash(newPassword, 10);

    // Cập nhật mật khẩu trong database
    await sequelize.query(
      `UPDATE "User" SET password = :newHashedPassword, is_first_login = false WHERE username = :username And password = :hashedPassword;`,
      {
        replacements: { newHashedPassword, hashedPassword, username },
        type: sequelize.QueryTypes.UPDATE,
      }
    );

    const token = jwt.sign(
      {
        ...existingUser,
        id: existingUser.id.toString(),
        updated_by: existingUser.updated_by?.toString(),
        created_by: existingUser.created_by?.toString(),
      },
      process.env.JWT_SECRET || "your_secret_key",
      { expiresIn: "24h" }
    );

    // Cập nhật cookie mới
    res.cookie("token", token, {
      httpOnly: false,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      path: "/",
    });

    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Error updating password:", err);
    return res.status(500).json({ error: "Failed to update password" });
  }
});

// Customer

// GET: Lấy danh sách khách hàng (phân trang)
app.get("/customers", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const result = await sequelize.query(
      `
      WITH customer_data AS (
        SELECT c.*, 
              u.username AS created_by,
              u2.username AS updated_by
        FROM "Customer" c
        LEFT JOIN "User" u ON c.created_by = u.id
        LEFT JOIN "User" u2 ON c.updated_by = u2.id
        ORDER BY c.id ASC
        LIMIT :limit OFFSET :offset
      )
      SELECT CAST((SELECT COUNT(*) FROM "Customer") AS INTEGER) AS total, 
            json_agg(customer_data) AS customers 
      FROM customer_data;
      `,
      {
        replacements: { limit, offset },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    const { total, customers } = result[0] || { total: 0, customers: [] };

    return res.json({
      data: customers,
      total,
      page,
      totalPages: Math.ceil(total / limit),
    });
  } catch (err) {
    console.error("Error fetching customers:", err);
    return res
      .status(500)
      .json({ error: "Error fetching customers", details: err });
  }
});

// PUT: Cập nhật khách hàng
app.put("/customers/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const {
      full_name,
      year_of_birth,
      phone_number,
      note,
      role_note,
      status,
      team_id,
      updated_by,
    } = req.body;

    if (!id) {
      return res.status(400).json({ error: "Customer ID is required" });
    }

    if (!updated_by) {
      return res.status(400).json({ error: "Updated by is required" });
    }

    // Kiểm tra khách hàng có tồn tại không
    const existingCustomer = await sequelize.query(
      `SELECT * FROM "Customer" WHERE id = :id LIMIT 1`,
      {
        replacements: { id },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (existingCustomer.length === 0) {
      return res.status(404).json({ error: "Customer not found" });
    }

    // Cập nhật thông tin khách hàng
    await sequelize.query(
      `UPDATE "Customer" 
       SET full_name = :full_name, 
           year_of_birth = :year_of_birth, 
           phone_number = :phone_number, 
           note = :note, 
           role_note = :role_note, 
           status = :status, 
           team_id = :team_id, 
           updated_by = :updated_by, 
           updated_at = NOW()
       WHERE id = :id`,
      {
        replacements: {
          id,
          full_name,
          year_of_birth,
          phone_number,
          note,
          role_note,
          status,
          team_id,
          updated_by,
        },
        type: sequelize.QueryTypes.UPDATE,
      }
    );

    return res.json({ message: "Customer updated successfully" });
  } catch (error) {
    console.error("Error updating customer:", error);
    return res.status(500).json({ error: "Failed to update customer" });
  }
});

// POST: Tạo khách hàng mới
app.post("/customers", async (req, res) => {
  try {
    const {
      full_name,
      year_of_birth,
      phone_number,
      note,
      role_note,
      status,
      team_id,
      updated_by,
    } = req.body;

    if (!phone_number) {
      return res.status(400).json({ error: "Phone number is required" });
    }

    // Kiểm tra số điện thoại đã tồn tại chưa
    const existingCustomer = await sequelize.query(
      `SELECT * FROM "Customer" WHERE phone_number = :phone_number LIMIT 1`,
      {
        replacements: { phone_number },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (existingCustomer.length > 0) {
      return res.status(400).json({ error: "Phone number already exists" });
    }

    // Thêm khách hàng mới
    await sequelize.query(
      `
      INSERT INTO "Customer" (
        full_name, year_of_birth, phone_number, note, role_note, 
        status, team_id, created_by, created_at, updated_by, updated_at
      ) 
      VALUES (
        :full_name, :year_of_birth, :phone_number, :note, :role_note,
        :status, :team_id, :updated_by, NOW(), :updated_by, NOW()
      )
      `,
      {
        replacements: {
          full_name,
          year_of_birth,
          phone_number,
          note,
          role_note,
          status,
          team_id,
          updated_by,
        },
        type: sequelize.QueryTypes.INSERT,
      }
    );

    return res.status(201).json({ message: "Customer Created Successfully" });
  } catch (error) {
    console.error("Error creating customer:", error);
    return res.status(500).json({ error: "Failed to create customer" });
  }
});

// PUT: Cập nhật trạng thái khách hàng
app.put("/customers", async (req, res) => {
  try {
    const { id, status, is_admin, updated_by } = req.body;

    if (!id || status === undefined || !updated_by) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    let updatedByInt = parseInt(updated_by, 10);
    const statusInt = parseInt(status, 10);

    if (isNaN(updatedByInt) || isNaN(statusInt)) {
      return res
        .status(400)
        .json({ error: "Invalid updated_by or status value" });
    }

    // Lấy trạng thái hiện tại của khách hàng
    const currentStatusResult = await sequelize.query(
      `SELECT status FROM "Customer" WHERE id = :id`,
      {
        replacements: { id },
        type: sequelize.QueryTypes.SELECT,
      }
    );

    if (!currentStatusResult.length) {
      return res.status(404).json({ error: "Customer not found" });
    }

    const currentStatus = currentStatusResult[0].status;

    if (currentStatus === "2") {
      updatedByInt = null;
    }

    // Kiểm tra điều kiện cập nhật trạng thái
    if (
      (currentStatus === "0" && (status === "1" || status === "2")) || // 0 → 1 hoặc 0 → 2
      (currentStatus === "1" && status === "2") || // 1 → 2
      (currentStatus === "2" && status === "1" && is_admin) // 2 → 1 (Chỉ admin)
    ) {
      await sequelize.query(
        `UPDATE "Customer" 
         SET status = :status, updated_by = :updatedByInt, updated_at = NOW() 
         WHERE id = :id`,
        {
          replacements: { status, updatedByInt, id },
          type: sequelize.QueryTypes.UPDATE,
        }
      );

      return res.json({ message: "Status updated successfully" });
    }

    return res.status(400).json({ error: "Invalid status transition" });
  } catch (err) {
    console.error("Error updating status:", err.stack);
    return res.status(500).json({ error: "Error updating status" });
  }
});

// DELETE: Xóa khách hàng theo ID
app.delete("/customers/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!id) {
      return res.status(400).json({ error: "Missing customer ID" });
    }

    const result = await sequelize.query(
      `DELETE FROM "Customer" WHERE id = :id`,
      { replacements: { id }, type: sequelize.QueryTypes.DELETE }
    );

    return res.json({ message: "Customer deleted successfully" });
  } catch (err) {
    console.error("Error deleting customer:", err.stack);
    return res.status(500).json({ error: "Internal server error" });
  }
});

//

/**
 * GET /api/employees
 * Lấy danh sách nhân viên với phân trang
 */
app.get("/employees", async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const query = `
      WITH user_data AS (
        SELECT u.*, 
               c.username AS created_by_username, 
               u2.username AS updated_by_username
        FROM "User" u
        LEFT JOIN "User" c ON u.created_by = c.id
        LEFT JOIN "User" u2 ON u.updated_by = u2.id
        WHERE u.is_admin = false
        ORDER BY u.id ASC
        LIMIT :limit OFFSET :offset
      )
      SELECT CAST((SELECT COUNT(*) FROM "User") AS INTEGER) AS total, 
             json_agg(user_data) AS users 
      FROM user_data;
    `;

    const result = await sequelize.query(query, {
      type: sequelize.QueryTypes.SELECT,
      replacements: { limit, offset },
    });

    const { total, users } = result[0] || { total: 0, users: [] };

    res.json({
      data: users,
      total: Number(total),
      page,
      totalPages: Math.ceil(Number(total) / limit),
    });
  } catch (err) {
    console.error("Error fetching users:", err);
    res
      .status(500)
      .json({ error: "Error fetching users", details: err.message });
  }
});

/**
 * POST /api/employees
 * Tạo nhân viên mới
 */
app.post("/employees", async (req, res) => {
  try {
    const { username, name, user_role, status, team_id } = req.body;

    if (!username || !name || !team_id) {
      return res
        .status(400)
        .json({ error: "Username, name, and team_id are required" });
    }

    const hashedPassword = await bcrypt.hash(username, 10);
    const isAdmin = user_role === "0";
    const isTeamLead = user_role === "1";
    const teamIdAsInt = parseInt(team_id, 10);

    if (isNaN(teamIdAsInt)) {
      return res
        .status(400)
        .json({ error: "Invalid team_id, it must be an integer" });
    }

    const query = `
      INSERT INTO "User" 
      (username, name, password, is_admin, is_team_lead, is_first_login, status, team_id, updated_at)
      VALUES 
      (:username, :name, :password, :isAdmin, :isTeamLead, true, :status, :teamId, NOW())
    `;

    await sequelize.query(query, {
      replacements: {
        username,
        name,
        password: hashedPassword,
        isAdmin,
        isTeamLead,
        status: status || "1",
        teamId: teamIdAsInt,
      },
    });

    res.status(201).json({
      message: "User created successfully",
      data: { username, name, team_id: teamIdAsInt },
    });
  } catch (err) {
    console.error("Error creating user:", err);
    res.status(500).json({ error: "Failed to create user" });
  }
});

/**
 * PUT /api/employees
 * Reset mật khẩu nhân viên
 */
app.put("/employees", async (req, res) => {
  try {
    const { id } = req.body;
    if (!id) {
      return res.status(400).json({ error: "User ID is required" });
    }

    const checkUserQuery = `SELECT COUNT(*)::int AS count FROM "User" WHERE id = :id`;
    const userExists = await sequelize.query(checkUserQuery, {
      replacements: { id },
      type: sequelize.QueryTypes.SELECT,
    });

    if (!userExists[0]?.count) {
      return res.status(404).json({ error: "User not found" });
    }

    const resetQuery = `UPDATE "User" SET is_first_login = TRUE WHERE id = :id`;
    await sequelize.query(resetQuery, { replacements: { id } });

    res.json({ message: "Reset password successfully" });
  } catch (error) {
    console.error("Error resetting password:", error);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

//

/**
 * GET /api/statistical
 * Lấy thống kê cuộc gọi theo team và role_note
 */
app.get("/statistical", async (req, res) => {
  try {
    const { role_note } = req.query;
    const normalizedRoleNote = role_note === "null" ? null : role_note;

    let whereClause = "";
    const replacements = {};

    if (normalizedRoleNote) {
      whereClause = `WHERE c.role_note = :role_note`;
      replacements.role_note = normalizedRoleNote;
    }

    const query = `
      SELECT COUNT(1) AS call_count, c.role_note AS caller, t.team_name
      FROM "Customer" AS c
      INNER JOIN "Team" AS t ON c.team_id = t.id
      ${whereClause}
      GROUP BY c.team_id, c.role_note, t.team_name
      ORDER BY call_count DESC;
    `;

    const callCounts = await sequelize.query(query, {
      type: sequelize.QueryTypes.SELECT,
      replacements,
    });

    const formattedCallCounts = callCounts.map((entry) => ({
      ...entry,
      call_count: Number(entry.call_count), // Fix BigInt serialization
    }));

    res.json({ data: formattedCallCounts });
  } catch (err) {
    console.error("Error fetching call counts:", err);
    res.status(500).json({ error: "Error fetching call counts" });
  }
});

//

/**
 * GET /api/team
 * Lấy danh sách các team (có hỗ trợ phân trang)
 */
app.get("/teams", async (req, res) => {
  try {
    const { page, limit } = req.query;
    const pageNum = parseInt(page, 10) || 1;
    const limitNum = parseInt(limit, 10) || 10;
    const offset = (pageNum - 1) * limitNum;

    if (!page || !limit) {
      // Lấy tất cả teams không phân trang
      const allTeams = await sequelize.query(
        `
        SELECT t.*, 
               u.username AS created_by, 
               u2.username AS updated_by
        FROM "Team" t
        LEFT JOIN "User" u ON t.created_by = u.id
        LEFT JOIN "User" u2 ON t.updated_by = u2.id
        ORDER BY t.id ASC
        `,
        { type: sequelize.QueryTypes.SELECT }
      );

      return res.json({
        data: allTeams,
        total: allTeams.length,
        page: 1,
        totalPages: 1,
      });
    }

    // Lấy teams có phân trang
    const teams = await sequelize.query(
      `
      SELECT t.*, 
             u.username AS created_by, 
             u2.username AS updated_by
      FROM "Team" t
      LEFT JOIN "User" u ON t.created_by = u.id
      LEFT JOIN "User" u2 ON t.updated_by = u2.id
      ORDER BY t.id ASC
      LIMIT :limitNum OFFSET :offset
      `,
      {
        type: sequelize.QueryTypes.SELECT,
        replacements: { limitNum, offset },
      }
    );

    // Đếm tổng số teams
    const countResult = await sequelize.query(
      `SELECT COUNT(*)::int AS total FROM "Team"`,
      { type: sequelize.QueryTypes.SELECT }
    );
    const total = countResult[0].total;

    return res.json({
      data: teams,
      total,
      page: pageNum,
      totalPages: Math.ceil(total / limitNum),
    });
  } catch (err) {
    console.error("Error fetching teams:", err);
    res.status(500).json({ error: "Error fetching teams" });
  }
});

/**
 * POST /api/team
 * Thêm mới một team
 */
app.post("/teams", async (req, res) => {
  try {
    const { team_name } = req.body;
    if (!team_name || typeof team_name !== "string") {
      return res.status(400).json({ error: "Team name is required" });
    }

    // Kiểm tra xem team đã tồn tại chưa
    const existingTeam = await sequelize.query(
      `SELECT * FROM "Team" WHERE team_name = :team_name LIMIT 1`,
      {
        type: sequelize.QueryTypes.SELECT,
        replacements: { team_name },
      }
    );

    if (existingTeam.length > 0) {
      return res.status(400).json({ error: "Team name already exists" });
    }

    // Tạo team mới
    await sequelize.query(
      `INSERT INTO "Team" (team_name, updated_at) VALUES (:team_name, NOW())`,
      {
        type: sequelize.QueryTypes.INSERT,
        replacements: { team_name },
      }
    );

    return res.status(201).json({
      message: "Tạo tổ thành công",
      data: { team_name },
    });
  } catch (error) {
    console.error("Error creating team:", error);
    res.status(500).json({ error: "Failed to create team" });
  }
});

/**
 * PUT /api/team/:id
 * Cập nhật thông tin team theo ID
 */
app.put("/teams/:id", async (req, res) => {
  try {
    const teamId = parseInt(req.params.id, 10);
    const { team_name, updated_by } = req.body; // `updated_by` là user cập nhật team

    if (!teamId || isNaN(teamId)) {
      return res.status(400).json({ error: "Invalid team ID" });
    }

    if (!team_name || typeof team_name !== "string") {
      return res.status(400).json({ error: "Team name is required" });
    }

    // Kiểm tra xem team có tồn tại không
    const existingTeam = await sequelize.query(
      `SELECT * FROM "Team" WHERE id = :teamId LIMIT 1`,
      {
        type: sequelize.QueryTypes.SELECT,
        replacements: { teamId },
      }
    );

    if (existingTeam.length === 0) {
      return res.status(404).json({ error: "Team not found" });
    }

    // Kiểm tra xem tên team mới đã tồn tại chưa (tránh trùng lặp)
    const duplicateTeam = await sequelize.query(
      `SELECT * FROM "Team" WHERE team_name = :team_name AND id != :teamId LIMIT 1`,
      {
        type: sequelize.QueryTypes.SELECT,
        replacements: { team_name, teamId },
      }
    );

    if (duplicateTeam.length > 0) {
      return res.status(400).json({ error: "Team name already exists" });
    }

    // Cập nhật team
    await sequelize.query(
      `
      UPDATE "Team"
      SET team_name = :team_name,
          updated_at = NOW(),
          updated_by = :updated_by
      WHERE id = :teamId
      `,
      {
        type: sequelize.QueryTypes.UPDATE,
        replacements: { team_name, updated_by, teamId },
      }
    );

    return res.json({
      message: "Cập nhật team thành công",
      data: { id: teamId, team_name, updated_by },
    });
  } catch (error) {
    console.error("Error updating team:", error);
    res.status(500).json({ error: "Failed to update team" });
  }
});

// Kết nối database và chạy server
const PORT = process.env.PORT || 5000;
connectDB().then(() => {
  app.listen(PORT, async () => {
    console.log(`🚀 Server is running on port ${PORT}`);
  });
});
