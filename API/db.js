// db.js
const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',          // 替换为你的MySQL用户名
  password: 'Wadwad2020a',   // 替换为你的MySQL密码
  database: 'lianyuan_database', // 替换为你的数据库名
  waitForConnections: true,
  connectionLimit: 10
});

// 测试连接
(async () => {
  try {
    const conn = await pool.getConnection();
    console.log('✅ MySQL连接成功');
    conn.release();
  } catch (err) {
    console.error('❌ MySQL连接失败:', err);
    process.exit(1); // 如果数据库连接失败，退出应用
  }
})();

module.exports = pool;