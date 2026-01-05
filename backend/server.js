const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;

/* =========================
   CONFIGURAÇÕES BÁSICAS
========================= */
app.use(express.json());

app.use(session({
    secret: 'daigyo-segredo-interno',
    resave: false,
    saveUninitialized: false
}));

/* =========================
   CAMINHOS
========================= */
const frontendPath = path.join(__dirname, '..', 'frontend');
const dbPath = path.join(__dirname, 'database', 'database.db');

/* =========================
   BANCO DE DADOS
========================= */
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Erro ao abrir banco:', err.message);
    } else {
        console.log('Banco de dados conectado com sucesso');
    }
});

// criar tabela de usuários
db.run(`
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT,
        email TEXT UNIQUE,
        senha TEXT,
        tipo TEXT,
        ativo INTEGER
    )
`);
// criar tabela de eventos
db.run(`
    CREATE TABLE IF NOT EXISTS eventos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT,
        descricao TEXT,
        data TEXT,
        ativo INTEGER
    )
`);
// criar tabela de materiais
db.run(`
    CREATE TABLE IF NOT EXISTS materiais (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        titulo TEXT,
        link TEXT,
        ativo INTEGER
    )
`);
// criar admin padrão (uma única vez)
db.get(
    `SELECT * FROM usuarios WHERE email = ?`,
    ['admin@daigyo.com'],
    async (err, row) => {
        if (!row) {
            const senhaHash = await bcrypt.hash('123456', 10);

            db.run(
                `INSERT INTO usuarios (nome, email, senha, tipo, ativo)
                 VALUES (?, ?, ?, ?, ?)`,
                ['Administrador', 'admin@daigyo.com', senhaHash, 'admin', 1]
            );

            console.log('Admin padrão criado: admin@daigyo.com / 123456');
        }
    }
);

/* =========================
   MIDDLEWARE DE SEGURANÇA
========================= */
function autenticar(req, res, next) {
    if (req.session.usuario) {
        next();
    } else {
        res.status(401).json({ mensagem: 'Não autorizado' });
    }
}

function apenasAdmin(req, res, next) {
    if (req.session.usuario && req.session.usuario.tipo === 'admin') {
        next();
    } else {
        res.status(403).json({ mensagem: 'Acesso restrito ao administrador' });
    }
}
// proteger páginas HTML
app.get('/admin.html', autenticar, apenasAdmin, (req, res) => {
    res.sendFile(path.join(frontendPath, 'admin.html'));
});

app.get('/aluno.html', autenticar, (req, res) => {
    res.sendFile(path.join(frontendPath, 'aluno.html'));
});
/* =========================
   FRONTEND
========================= */
app.use(express.static(frontendPath));

app.get('/', (req, res) => {
    res.sendFile(path.join(frontendPath, 'index.html'));
});

/* =========================
   LOGIN
========================= */
app.post('/login', (req, res) => {
    const { email, senha } = req.body;

    db.get(
        `SELECT * FROM usuarios WHERE email = ? AND ativo = 1`,
        [email],
        async (err, usuario) => {
            if (!usuario) {
                return res.json({ sucesso: false, mensagem: 'Usuário não encontrado' });
            }

            const senhaOk = await bcrypt.compare(senha, usuario.senha);

            if (!senhaOk) {
                return res.json({ sucesso: false, mensagem: 'Senha incorreta' });
            }

            req.session.usuario = {
                id: usuario.id,
                nome: usuario.nome,
                tipo: usuario.tipo
            };

            res.json({
                sucesso: true,
                tipo: usuario.tipo
            });
        }
    );
});

/* =========================
   ROTAS PROTEGIDAS
========================= */
app.get('/aluno', autenticar, (req, res) => {
    res.json({
        mensagem: `Bem-vindo à área do aluno, ${req.session.usuario.nome}`
    });
});

app.get('/admin', autenticar, apenasAdmin, (req, res) => {
    res.json({
        mensagem: `Bem-vindo ao painel administrativo, ${req.session.usuario.nome}`
    });
});

/* =========================
   LOGOUT
========================= */
app.post('/logout', (req, res) => {
    req.session.destroy(() => {
        res.json({ sucesso: true });
    });
});
/* =========================
   ADMIN — USUÁRIOS
========================= */

// listar usuários (somente admin)
app.get('/admin/usuarios', autenticar, apenasAdmin, (req, res) => {
    db.all(
        `SELECT id, nome, email, tipo, ativo FROM usuarios`,
        [],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ erro: 'Erro ao listar usuários' });
            }
            res.json(rows);
        }
    );
});

// cadastrar aluno (somente admin)
app.post('/admin/usuarios', autenticar, apenasAdmin, async (req, res) => {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
        return res.json({ sucesso: false, mensagem: 'Dados incompletos' });
    }

    const senhaHash = await bcrypt.hash(senha, 10);

    db.run(
        `INSERT INTO usuarios (nome, email, senha, tipo, ativo)
         VALUES (?, ?, ?, ?, ?)`,
        [nome, email, senhaHash, 'aluno', 1],
        function (err) {
            if (err) {
                return res.json({ sucesso: false, mensagem: 'Erro ao cadastrar' });
            }
            res.json({ sucesso: true });
        }
    );
});

// ativar / desativar usuário
app.put('/admin/usuarios/:id', autenticar, apenasAdmin, (req, res) => {
    const { ativo } = req.body;
    const { id } = req.params;

    db.run(
        `UPDATE usuarios SET ativo = ? WHERE id = ?`,
        [ativo, id],
        function () {
            res.json({ sucesso: true });
        }
    );
});
/* =========================
   ALUNO — CONTEÚDO
========================= */

// dados do aluno logado
app.get('/aluno/dados', autenticar, (req, res) => {
    res.json({
        nome: req.session.usuario.nome,
        tipo: req.session.usuario.tipo
    });
});

// comunicados simples (exemplo)
app.get('/aluno/comunicados', autenticar, (req, res) => {
    res.json([
        {
            titulo: 'Bem-vindo',
            texto: 'Seja bem-vindo à área do aluno Daigyo.'
        },
        {
            titulo: 'Treinos',
            texto: 'Confira os horários atualizados dos treinos.'
        }
    ]);
});
/* =========================
   ADMIN — EVENTOS
========================= */

// listar eventos (admin)
app.get('/admin/eventos', autenticar, apenasAdmin, (req, res) => {
    db.all(
        `SELECT * FROM eventos`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ erro: 'Erro ao listar eventos' });
            res.json(rows);
        }
    );
});

// criar evento (admin)
app.post('/admin/eventos', autenticar, apenasAdmin, (req, res) => {
    const { titulo, descricao, data } = req.body;

    if (!titulo || !data) {
        return res.json({ sucesso: false, mensagem: 'Título e data são obrigatórios' });
    }

    db.run(
        `INSERT INTO eventos (titulo, descricao, data, ativo)
         VALUES (?, ?, ?, ?)`,
        [titulo, descricao || '', data, 1],
        function (err) {
            if (err) return res.json({ sucesso: false });
            res.json({ sucesso: true });
        }
    );
});

// ativar / desativar evento (admin)
app.put('/admin/eventos/:id', autenticar, apenasAdmin, (req, res) => {
    const { ativo } = req.body;
    const { id } = req.params;

    db.run(
        `UPDATE eventos SET ativo = ? WHERE id = ?`,
        [ativo, id],
        function () {
            res.json({ sucesso: true });
        }
    );
});
/* =========================
   ADMIN — EVENTOS
========================= */

// listar eventos (admin)
app.get('/admin/eventos', autenticar, apenasAdmin, (req, res) => {
    db.all(
        `SELECT * FROM eventos`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ erro: 'Erro ao listar eventos' });
            res.json(rows);
        }
    );
});

// criar evento (admin)
app.post('/admin/eventos', autenticar, apenasAdmin, (req, res) => {
    console.log('EVENTO RECEBIDO:', req.body);

    const { titulo, descricao, data } = req.body;

    if (!titulo || !data) {
        return res.json({ sucesso: false, mensagem: 'Dados incompletos' });
    }

    db.run(
        `INSERT INTO eventos (titulo, descricao, data, ativo)
         VALUES (?, ?, ?, ?)`,
        [titulo, descricao || '', data, 1],
        function (err) {
            if (err) {
                console.error(err);
                return res.json({ sucesso: false });
            }
            res.json({ sucesso: true });
        }
    );
});

// ativar / desativar evento (admin)
app.put('/admin/eventos/:id', autenticar, apenasAdmin, (req, res) => {
    const { ativo } = req.body;
    const { id } = req.params;

    db.run(
        `UPDATE eventos SET ativo = ? WHERE id = ?`,
        [ativo, id],
        function () {
            res.json({ sucesso: true });
        }
    );
});

/* =========================
   ALUNO — EVENTOS
========================= */

// listar eventos ativos (aluno)
app.get('/aluno/eventos', autenticar, (req, res) => {
    db.all(
        `SELECT titulo, descricao, data FROM eventos WHERE ativo = 1 ORDER BY data`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ erro: 'Erro ao listar eventos' });
            res.json(rows);
        }
    );
});
/* =========================
   ADMIN — MATERIAIS
========================= */

// listar materiais (admin)
app.get('/admin/materiais', autenticar, apenasAdmin, (req, res) => {
    db.all(`SELECT * FROM materiais`, [], (err, rows) => {
        if (err) return res.status(500).json({ erro: 'Erro ao listar materiais' });
        res.json(rows);
    });
});

// criar material (admin)
app.post('/admin/materiais', autenticar, apenasAdmin, (req, res) => {
    const { titulo, link } = req.body;
    if (!titulo || !link) {
        return res.json({ sucesso: false, mensagem: 'Dados incompletos' });
    }
    db.run(
        `INSERT INTO materiais (titulo, link, ativo) VALUES (?, ?, ?)`,
        [titulo, link, 1],
        function (err) {
            if (err) return res.json({ sucesso: false });
            res.json({ sucesso: true });
        }
    );
});

// ativar/desativar material (admin)
app.put('/admin/materiais/:id', autenticar, apenasAdmin, (req, res) => {
    const { ativo } = req.body;
    const { id } = req.params;
    db.run(`UPDATE materiais SET ativo = ? WHERE id = ?`, [ativo, id], () => {
        res.json({ sucesso: true });
    });
});

/* =========================
   ALUNO — MATERIAIS
========================= */

// listar materiais ativos (aluno)
app.get('/aluno/materiais', autenticar, (req, res) => {
    db.all(
        `SELECT titulo, link FROM materiais WHERE ativo = 1`,
        [],
        (err, rows) => {
            if (err) return res.status(500).json({ erro: 'Erro ao listar materiais' });
            res.json(rows);
        }
    );
});
/* =========================
   INICIAR SERVIDOR
========================= */
app.listen(PORT, () => {
    console.log(`Servidor ativo em http://localhost:${PORT}`);
});