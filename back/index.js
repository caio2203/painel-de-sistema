// Este backend foi projetado para funcionar tanto com SQLite (desenvolvimento/local) quanto com MySQL (produção), facilitando a portabilidade.
// Para alternar entre bancos, basta ajustar a variável de ambiente DB_TYPE para 'sqlite' ou 'mysql'.
// As funções de conexão e queries estão preparadas para ambos os bancos, mas é importante revisar os tipos de dados e sintaxe SQL ao migrar.

// Importação dos módulos necessários para o backend funcionar
const express = require('express'); // Framework web para Node.js
const cors = require('cors'); // Middleware para habilitar CORS
const bodyParser = require('body-parser'); // Middleware para parsear JSON e urlencoded
const path = require('path'); // Utilitário para manipulação de caminhos
const bcrypt = require('bcrypt'); // Biblioteca para hash de senhas (não utilizado neste projeto, mas importado)
const jwt = require('jsonwebtoken'); // Biblioteca para geração e verificação de tokens JWT

// Aqui importamos os drivers dos dois bancos. Só será usado o necessário conforme o DB_TYPE.
const sqlite3 = require('sqlite3').verbose(); // Driver SQLite
const { open } = require('sqlite'); // Abstração para abrir conexões SQLite
// Para MySQL, descomente a linha abaixo e instale o pacote mysql2 (npm install mysql2)
// const mysql = require('mysql2/promise');

// Defina o tipo de banco de dados via variável de ambiente: 'sqlite' (padrão) ou 'mysql'
const DB_TYPE = process.env.DB_TYPE || 'sqlite';

// Configurações globais do sistema, incluindo porta, dados do banco e segredo JWT
const CONFIG = {
  PORTA: process.env.PORTA || 3000,
  // As configurações abaixo só são usadas se DB_TYPE for 'mysql'
  BANCO_DE_DADOS: {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'seu_usuario',
    password: process.env.DB_PASSWORD || 'sua_senha',
    database: process.env.DB_NAME || 'hospital_db'
  },
  CHAVE_SECRETA_JWT: process.env.JWT_SECRET || 'sua_chave_secreta_aqui',
  ROUNDS_SAL: 10
};

const app = express(); // Inicializa a aplicação Express

// Middlewares globais
app.use(cors()); // Habilita CORS para todas as rotas
app.use(bodyParser.json()); // Permite receber JSON no body
app.use(bodyParser.urlencoded({ extended: true })); // Permite receber urlencoded
app.use(express.static(path.join(__dirname, 'public'))); // Serve arquivos estáticos da pasta 'public'

// Middleware de autenticação JWT para proteger rotas (não utilizado em todas as rotas)
const autenticarToken = (req, res, next) => {
  // Extrai o token do header Authorization
  const cabecalhoAutorizacao = req.headers['authorization'];
  const token = cabecalhoAutorizacao && cabecalhoAutorizacao.split(' ')[1];
  if (token == null) return res.sendStatus(401); // Sem token
  jwt.verify(token, CONFIG.CHAVE_SECRETA_JWT, (err, usuario) => {
    if (err) return res.sendStatus(403); // Token inválido
    req.usuario = usuario; // Adiciona usuário decodificado ao request
    next();
  });
};

// Função de conexão genérica: retorna a conexão correta conforme o banco
// Facilita a portabilidade entre SQLite e MySQL
async function conectarBancoDeDados() {
  if (DB_TYPE === 'sqlite') {
    // Conexão SQLite (arquivo local)
    return open({
      filename: path.join(__dirname, '../painel-de-sistema-bd.db'),
      driver: sqlite3.Database
    });
  } else if (DB_TYPE === 'mysql') {
    // Conexão MySQL (produção). Certifique-se de instalar o pacote mysql2.
    // Descomente a linha de importação do mysql2 no topo do arquivo.
    const mysql = require('mysql2/promise');
    return mysql.createConnection(CONFIG.BANCO_DE_DADOS);
  }
  throw new Error('Tipo de banco de dados não suportado');
}

// Função utilitária para SELECT ALL, abstraindo diferenças entre bancos
// Retorna todos os resultados de uma query
async function selectAll(db, query, params) {
  if (DB_TYPE === 'sqlite') {
    return db.all(query, params);
  } else if (DB_TYPE === 'mysql') {
    const [rows] = await db.query(query, params);
    return rows;
  }
}

// Função utilitária para INSERT/UPDATE/DELETE
// Executa queries de modificação de dados
async function runQuery(db, query, params) {
  if (DB_TYPE === 'sqlite') {
    return db.run(query, params);
  } else if (DB_TYPE === 'mysql') {
    const [result] = await db.query(query, params);
    return result;
  }
}

// ================= ROTAS PRINCIPAIS =====================

// Rota de login do médico (sem senha)
// Recebe { usuario } no body e retorna token JWT e dados do médico
app.post('/login', async (req, res) => {
  try {
    let { usuario } = req.body;
    usuario = usuario.trim().toLowerCase();
    const db = await conectarBancoDeDados();
    const usuarios = await selectAll(db, 'SELECT * FROM medicos WHERE LOWER(TRIM(usuario)) = ?', [usuario]);
    if (usuarios.length === 0) {
      if (DB_TYPE === 'sqlite') await db.close();
      return res.status(400).json({ mensagem: 'Usuário não encontrado' });
    }
    const usuarioEncontrado = usuarios[0];
    // Gera token JWT para autenticação
    const token = jwt.sign(
      { id: usuarioEncontrado.id, usuario: usuarioEncontrado.usuario, nome: usuarioEncontrado.nome }, 
      CONFIG.CHAVE_SECRETA_JWT, 
      { expiresIn: '24h' }
    );
    if (DB_TYPE === 'sqlite') await db.close();
    res.json({ 
      token, 
      usuario: { 
        id: usuarioEncontrado.id, 
        nome: usuarioEncontrado.nome, 
        sala: usuarioEncontrado.sala, 
        usuario: usuarioEncontrado.usuario 
      } 
    });
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro no login', erro: erro.message });
  }
});

// Rota de login da recepção (sem senha)
// Recebe { usuario } no body e retorna os dados do recepcionista se encontrado
app.post('/login-recepcao', async (req, res) => {
  try {
    let { usuario } = req.body;
    usuario = usuario.trim().toLowerCase();
    const db = await conectarBancoDeDados();
    // Busca recepcionista pelo usuário (case/trim insensitive)
    const usuarios = await selectAll(db, 'SELECT * FROM recepcionistas WHERE LOWER(TRIM(usuario)) = ?', [usuario]);
    if (usuarios.length === 0) {
      if (DB_TYPE === 'sqlite') await db.close();
      return res.status(400).json({ mensagem: 'Usuário não encontrado' });
    }
    const usuarioEncontrado = usuarios[0];
    // Gera um token JWT para manter padrão, mas pode ser ignorado se não for usar autenticação
    const token = jwt.sign(
      { id: usuarioEncontrado.id, usuario: usuarioEncontrado.usuario, nome: usuarioEncontrado.nome },
      CONFIG.CHAVE_SECRETA_JWT,
      { expiresIn: '24h' }
    );
    if (DB_TYPE === 'sqlite') await db.close();
    res.json({
      token,
      usuario: {
        id: usuarioEncontrado.id,
        nome: usuarioEncontrado.nome,
        usuario: usuarioEncontrado.usuario
      }
    });
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro no login da recepção', erro: erro.message });
  }
});

// Rota de cadastro de médicos (usada pelo frontend para registrar médicos no banco de dados)
// Recebe { nome, sala, usuario } no body e cadastra novo médico
app.post('/medicos', async (req, res) => {
  try {
    let { nome, sala, usuario } = req.body;
    usuario = usuario.trim().toLowerCase();
    const db = await conectarBancoDeDados();
    // Verifica se já existe médico com o mesmo usuário
    const existente = await selectAll(db, 'SELECT * FROM medicos WHERE LOWER(TRIM(usuario)) = ?', [usuario]);
    if (existente.length > 0) {
      if (DB_TYPE === 'sqlite') await db.close();
      return res.status(400).json({ mensagem: 'Usuário já cadastrado' });
    }
    // Insere novo médico
    const resultado = await runQuery(db, 'INSERT INTO medicos (nome, sala, usuario) VALUES (?, ?, ?)', [nome, sala, usuario]);
    const insertId = DB_TYPE === 'sqlite' ? resultado.lastID : resultado.insertId;
    res.status(201).json({ 
      mensagem: 'Médico cadastrado com sucesso',
      medico: { 
        id: insertId,
        nome, 
        sala, 
        usuario 
      }
    });
    if (DB_TYPE === 'sqlite') await db.close();
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao cadastrar médico', erro: erro.message });
  }
});

// Rota para obter médicos (agora aceita ?usuario=...)
// Se passar ?usuario=, retorna apenas o médico correspondente; senão, retorna todos
app.get('/medicos', async (req, res) => {
  try {
    const db = await conectarBancoDeDados();
    const usuario = req.query.usuario && req.query.usuario.trim().toLowerCase();
    if (usuario) {
      // Busca apenas o médico pelo usuário
      const medicos = await selectAll(db, 'SELECT id, nome, sala, usuario FROM medicos WHERE LOWER(TRIM(usuario)) = ?', [usuario]);
      if (medicos.length === 0) {
        if (DB_TYPE === 'sqlite') await db.close();
        return res.status(404).json({ mensagem: 'Médico não encontrado' });
      }
      const medico = medicos[0];
      if (DB_TYPE === 'sqlite') await db.close();
      return res.json({ medico });
    } else {
      // Listagem geral de todos os médicos
      const medicos = await selectAll(db, 'SELECT id, nome, sala, usuario FROM medicos', []);
      // Para cada médico, busca os pacientes vinculados
      for (let medico of medicos) {
        const pacientes = await selectAll(db, 'SELECT nome FROM pacientes WHERE medico_id = ?', [medico.id]);
        medico.pacientes = pacientes.map(p => p.nome);
      }
      res.status(200).json({ medicos });
      if (DB_TYPE === 'sqlite') await db.close();
    }
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao buscar médicos', erro: erro.message });
  }
});

// Rota para criar chamadas (agora sem autenticação)
// Recebe { paciente, medico, sala, horario } no body e cria uma nova chamada
app.post('/chamadas', async (req, res) => {
  try {
    const { paciente, medico, sala, horario } = req.body;
    const db = await conectarBancoDeDados();
    // INSERT adaptado para ambos os bancos
    const resultado = await runQuery(db, 'INSERT INTO chamadas (paciente, medico, sala, horario, status) VALUES (?, ?, ?, ?, ?)', [paciente, medico, sala, horario, 'pendente']);
    const insertId = DB_TYPE === 'sqlite' ? resultado.lastID : resultado.insertId;
    const chamada = {
      id: insertId,
      paciente,
      medico,
      sala,
      horario
    };
    res.status(201).json({ mensagem: 'Chamada criada com sucesso', chamada });
    if (DB_TYPE === 'sqlite') await db.close();
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao criar chamada', erro: erro.message });
  }
});

// Rota para obter pacientes do médico pelo usuario (sem autenticação)
// Se passar ?usuario=, retorna pacientes do médico correspondente e do dia atual; senão, retorna todos os pacientes (para TV)
app.get('/pacientes', async (req, res) => {
  try {
    const db = await conectarBancoDeDados();
    const usuario = req.query.usuario && req.query.usuario.trim().toLowerCase();
    const dataAtual = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    if (usuario) {
      // Busca o médico pelo usuario
      const medicos = await selectAll(db, 'SELECT id FROM medicos WHERE LOWER(TRIM(usuario)) = ?', [usuario]);
      if (medicos.length === 0) {
        if (DB_TYPE === 'sqlite') await db.close();
        return res.status(404).json({ mensagem: 'Médico não encontrado' });
      }
      const medicoId = medicos[0].id;
      // Filtra por status e data_criacao = hoje
      const pacientes = await selectAll(db, 'SELECT * FROM pacientes WHERE medico_id = ? AND status = ? AND data_criacao = ?', [medicoId, 'pronto para atender', dataAtual]);
      if (DB_TYPE === 'sqlite') await db.close();
      return res.status(200).json({ pacientes });
    } else {
      // Se não passar usuario, retorna todos os pacientes (comum para TV)
      const pacientes = await selectAll(db, 'SELECT id, nome, status, medico_id FROM pacientes', []);
      res.status(200).json({ pacientes });
      if (DB_TYPE === 'sqlite') await db.close();
    }
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao buscar pacientes', erro: erro.message });
  }
});

// Rota para listar todos os pacientes (sem autenticação, para uso na TV)
// Retorna todos os pacientes cadastrados, independente do médico ou status
app.get('/pacientes-todos', async (req, res) => {
  try {
    const db = await conectarBancoDeDados();
    const pacientes = await selectAll(db, 'SELECT id, nome, status, medico_id, data_criacao FROM pacientes', []);
    res.status(200).json({ pacientes });
    if (DB_TYPE === 'sqlite') await db.close();
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao buscar pacientes', erro: erro.message });
  }
});

// Rota de cadastro de recepcionistas (usada pelo frontend para registrar recepcionistas no banco de dados)
// Recebe { nome, usuario } no body e cadastra novo recepcionista
app.post('/recepcionistas', async (req, res) => {
  try {
    let { nome, usuario } = req.body;
    usuario = usuario.trim().toLowerCase();
    const db = await conectarBancoDeDados();
    // Garante que a tabela existe (útil para ambiente de desenvolvimento)
    await db.exec(`CREATE TABLE IF NOT EXISTS recepcionistas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      usuario TEXT NOT NULL UNIQUE
    );`);
    // Verifica se já existe recepcionista com o mesmo usuário
    const existente = await selectAll(db, 'SELECT * FROM recepcionistas WHERE LOWER(TRIM(usuario)) = ?', [usuario]);
    if (existente.length > 0) {
      if (DB_TYPE === 'sqlite') await db.close();
      return res.status(400).json({ mensagem: 'Usuário já cadastrado' });
    }
    // Insere novo recepcionista
    const resultado = await runQuery(db, 'INSERT INTO recepcionistas (nome, usuario) VALUES (?, ?)', [nome, usuario]);
    const insertId = DB_TYPE === 'sqlite' ? resultado.lastID : resultado.insertId;
    res.status(201).json({ 
      mensagem: 'Recepcionista cadastrado com sucesso',
      recepcionista: {
        id: insertId,
        nome,
        usuario
      }
    });
    if (DB_TYPE === 'sqlite') await db.close();
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao cadastrar recepcionista', erro: erro.message });
  }
});

// Rota de cadastro de pacientes (usada pelo frontend para registrar pacientes vinculados a um médico)
// Recebe { nome, status, medico_id } no body e cadastra novo paciente
// Rota de cadastro de pacientes - Versão melhorada
app.post('/pacientes', async (req, res) => {
  let db;
  try {
    const { nome, status, medico_id } = req.body;
    
    // Validações básicas
    if (!nome || !medico_id) {
      return res.status(400).json({ 
        sucesso: false,
        mensagem: 'Nome do paciente e ID do médico são obrigatórios' 
      });
    }

    db = await conectarBancoDeDados();
    const dataAtual = new Date().toISOString().slice(0, 10);

    // Verifica se o médico existe
    const medicoExiste = await selectAll(db, 'SELECT id FROM medicos WHERE id = ?', [medico_id]);
    if (medicoExiste.length === 0) {
      return res.status(404).json({
        sucesso: false,
        mensagem: 'Médico não encontrado'
      });
    }

    // Insere o paciente com tratamento de erro específico
    const resultado = await runQuery(
      db, 
      'INSERT INTO pacientes (nome, status, medico_id, data_criacao) VALUES (?, ?, ?, ?)', 
      [nome, status || 'pendente', medico_id, dataAtual]
    );

    const insertId = DB_TYPE === 'sqlite' ? resultado.lastID : resultado.insertId;

    res.status(201).json({
      sucesso: true,
      paciente: {
        id: insertId,
        nome,
        status: status || 'pendente',
        medico_id,
        data_criacao: dataAtual
      }
    });

  } catch (erro) {
    console.error('Erro no cadastro de paciente:', erro);
    res.status(500).json({ 
      sucesso: false,
      mensagem: 'Erro ao cadastrar paciente',
      erro: erro.message 
    });
  } finally {
    if (db && DB_TYPE === 'sqlite') {
      try {
        await db.close();
      } catch (erroFechamento) {
        console.error('Erro ao fechar conexão:', erroFechamento);
      }
    }
  }
});

// Rota para listar recepcionistas (usada pelo frontend para exibir todos os recepcionistas cadastrados)
app.get('/recepcionistas', async (req, res) => {
  try {
    const db = await conectarBancoDeDados();
    const recepcionistas = await selectAll(db, 'SELECT id, nome, usuario FROM recepcionistas', []);
    res.status(200).json({ recepcionistas });
    if (DB_TYPE === 'sqlite') await db.close();
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao buscar recepcionistas', erro: erro.message });
  }
});

// Rota para editar recepcionista (usada pelo frontend para editar dados de um recepcionista)
// Recebe { nome, usuario } no body e atualiza o recepcionista pelo id
app.put('/recepcionistas/:id', async (req, res) => {
  try {
    const { id } = req.params;
    let { nome, usuario } = req.body;
    usuario = usuario.trim().toLowerCase();
    const db = await conectarBancoDeDados();
    // Verifica se já existe outro recepcionista com o mesmo usuário
    const existente = await selectAll(db, 'SELECT * FROM recepcionistas WHERE LOWER(TRIM(usuario)) = ? AND id != ?', [usuario, id]);
    if (existente.length > 0) {
      if (DB_TYPE === 'sqlite') await db.close();
      return res.status(400).json({ mensagem: 'Usuário já cadastrado para outro recepcionista' });
    }
    // Atualiza os dados do recepcionista
    const resultado = await runQuery(db, 'UPDATE recepcionistas SET nome = ?, usuario = ? WHERE id = ?', [nome, usuario, id]);
    if (DB_TYPE === 'sqlite') await db.close();
    if (resultado.changes === 0) {
      return res.status(404).json({ mensagem: 'Recepcionista não encontrado' });
    }
    res.json({ mensagem: 'Recepcionista atualizado com sucesso' });
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao atualizar recepcionista', erro: erro.message });
  }
});

// Rota para excluir recepcionista
// Remove recepcionista pelo id
app.delete('/recepcionistas/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const db = await conectarBancoDeDados();
    const resultado = await runQuery(db, 'DELETE FROM recepcionistas WHERE id = ?', [id]);
    if (DB_TYPE === 'sqlite') await db.close();
    if (resultado.changes === 0) {
      return res.status(404).json({ sucesso: false, mensagem: 'Recepcionista não encontrado' });
    }
    res.json({ sucesso: true });
  } catch (erro) {
    res.status(500).json({ sucesso: false, mensagem: 'Erro ao excluir recepcionista', erro: erro.message });
  }
});

// Rota para excluir médico
// Remove médico pelo id
app.delete('/medicos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const db = await conectarBancoDeDados();
    const resultado = await runQuery(db, 'DELETE FROM medicos WHERE id = ?', [id]);
    if (DB_TYPE === 'sqlite') await db.close();
    if (resultado.changes === 0) {
      return res.status(404).json({ sucesso: false, mensagem: 'Médico não encontrado' });
    }
    res.json({ sucesso: true });
  } catch (erro) {
    res.status(500).json({ sucesso: false, mensagem: 'Erro ao excluir médico', erro: erro.message });
  }
});

// Rota para excluir paciente pelo ID
// Remove paciente pelo id
app.delete('/pacientes/:id', async (req, res) => {
  try {
    const db = await conectarBancoDeDados();
    const pacienteId = req.params.id;
    const resultado = await runQuery(db, 'DELETE FROM pacientes WHERE id = ?', [pacienteId]);
    if (DB_TYPE === 'sqlite') await db.close();
    if (resultado.changes > 0 || resultado.affectedRows > 0) {
      res.json({ sucesso: true, mensagem: 'Paciente excluído com sucesso.' });
    } else {
      res.status(404).json({ sucesso: false, mensagem: 'Paciente não encontrado.' });
    }
  } catch (erro) {
    res.status(500).json({ sucesso: false, mensagem: 'Erro ao excluir paciente', erro: erro.message });
  }
});

// Rota para editar status do paciente
// Recebe { status } no body e atualiza o status do paciente pelo id
app.put('/pacientes/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;
    const db = await conectarBancoDeDados();
    await runQuery(db, 'UPDATE pacientes SET status = ? WHERE id = ?', [status, id]);
    res.json({ sucesso: true });
    if (DB_TYPE === 'sqlite') await db.close();
  } catch (erro) {
    res.status(500).json({ sucesso: false, mensagem: 'Erro ao atualizar status do paciente', erro: erro.message });
  }
});

// Rota para editar médico (usada pelo frontend para editar dados de um médico)
// Recebe { nome, sala, usuario } no body e atualiza o médico pelo id
app.put('/medicos/:id', async (req, res) => {
  try {
    const { id } = req.params;
    let { nome, sala, usuario } = req.body;
    usuario = usuario.trim().toLowerCase();
    const db = await conectarBancoDeDados();
    // Verifica se já existe outro médico com o mesmo usuário
    const existente = await selectAll(db, 'SELECT * FROM medicos WHERE LOWER(TRIM(usuario)) = ? AND id != ?', [usuario, id]);
    if (existente.length > 0) {
      if (DB_TYPE === 'sqlite') await db.close();
      return res.status(400).json({ mensagem: 'Usuário já cadastrado para outro médico' });
    }
    // Atualiza os dados do médico
    const resultado = await runQuery(db, 'UPDATE medicos SET nome = ?, sala = ?, usuario = ? WHERE id = ?', [nome, sala, usuario, id]);
    if (DB_TYPE === 'sqlite') await db.close();
    if (resultado.changes === 0) {
      return res.status(404).json({ mensagem: 'Médico não encontrado' });
    }
    res.json({ mensagem: 'Médico atualizado com sucesso' });
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao atualizar médico', erro: erro.message });
  }
});

// Função para inicializar as tabelas do banco de dados SQLite
// Cria as tabelas de médicos, recepcionistas e pacientes caso não existam
async function inicializarBancoDeDados() {
  try {
    const db = await conectarBancoDeDados();
    if (DB_TYPE === 'sqlite') {
      // Criação da tabela de médicos
      await db.exec(`CREATE TABLE IF NOT EXISTS medicos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        sala TEXT NOT NULL,
        usuario TEXT NOT NULL UNIQUE
      );`);
      // Criação da tabela de recepcionistas
      await db.exec(`CREATE TABLE IF NOT EXISTS recepcionistas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        usuario TEXT NOT NULL UNIQUE
      );`);
      // Criação da tabela de pacientes
      await db.exec(`CREATE TABLE IF NOT EXISTS pacientes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nome TEXT NOT NULL,
        medico_id INTEGER NOT NULL,
        status TEXT NOT NULL,
        data_criacao TEXT NOT NULL,
        FOREIGN KEY (medico_id) REFERENCES medicos(id)
      );`);
    }
    if (DB_TYPE === 'sqlite') await db.close();
  } catch (erro) {
    console.error('Erro ao inicializar o banco de dados:', erro.message);
  }
}

// Rota GET / para teste de conexão e integração com o frontend
// Apenas retorna mensagem simples para indicar que o backend está rodando
app.get('/', (req, res) => {
  res.send('Backend rodando! Rota raiz disponível para integração com o frontend.');
});

// ROTA DE POPULAÇÃO DE DADOS DE TESTE (apenas para ambiente local)
// Esta rota insere médicos, recepcionistas e pacientes de exemplo no banco de dados para facilitar testes.
// Só pode ser acessada a partir de 127.0.0.1
app.post('/popular-dados-teste', async (req, res) => {
  if (req.ip !== '::1' && req.ip !== '127.0.0.1' && req.ip !== '::ffff:127.0.0.1') {
    return res.status(403).json({ mensagem: 'Acesso negado: só pode ser executado localmente.' });
  }
  try {
    const db = await conectarBancoDeDados();
    // Médicos de exemplo
    const medicos = [
      { nome: 'João Silva', sala: '101', usuario: 'joaosilva' },
      { nome: 'Maria Souza', sala: '102', usuario: 'mariasouza' }
    ];
    for (const medico of medicos) {
      await runQuery(db, 'INSERT OR IGNORE INTO medicos (nome, sala, usuario) VALUES (?, ?, ?)', [medico.nome, medico.sala, medico.usuario]);
    }
    // Recepcionistas de exemplo
    const recepcionistas = [
      { nome: 'Ana Paula', usuario: 'anapaula' },
      { nome: 'Carlos Lima', usuario: 'carloslima' }
    ];
    for (const recep of recepcionistas) {
      await runQuery(db, 'INSERT OR IGNORE INTO recepcionistas (nome, usuario) VALUES (?, ?)', [recep.nome, recep.usuario]);
    }
    // Pacientes de exemplo vinculados ao médico 1 (João Silva)
    const pacientes = [
      { nome: 'Paciente 1', medico_id: 1, status: 'chegou' },
      { nome: 'Paciente 2', medico_id: 1, status: 'pendente' },
      { nome: 'Paciente 3', medico_id: 2, status: 'chegou' }
    ];
    for (const paciente of pacientes) {
      await runQuery(db, 'INSERT OR IGNORE INTO pacientes (nome, medico_id, status) VALUES (?, ?, ?)', [paciente.nome, paciente.medico_id, paciente.status]);
    }
    if (DB_TYPE === 'sqlite') await db.close();
    res.json({ mensagem: 'Dados de teste populados com sucesso!' });
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao popular dados de teste', erro: erro.message });
  }
});

// Rota para obter as últimas chamadas (para a TV)
// Retorna as 5 últimas chamadas cadastradas
app.get('/chamadas', async (req, res) => {
  try {
    const db = await conectarBancoDeDados();
    // Busca as 5 últimas chamadas
    const chamadas = await selectAll(db, 'SELECT id, paciente, medico, sala, horario FROM chamadas ORDER BY id DESC LIMIT 5', []);
    if (DB_TYPE === 'sqlite') await db.close();
    res.status(200).json({ chamadas });
  } catch (erro) {
    res.status(500).json({ mensagem: 'Erro ao buscar chamadas', erro: erro.message });
  }
});

// Rota para limpar todas as chamadas (usada pela recepção para limpar a TV)
// Remove todas as chamadas cadastradas
app.delete('/chamadas', async (req, res) => {
  try {
    const db = await conectarBancoDeDados();
    await runQuery(db, 'DELETE FROM chamadas', []);
    if (DB_TYPE === 'sqlite') await db.close();
    res.json({ sucesso: true, mensagem: 'Chamadas limpas com sucesso!' });
  } catch (erro) {
    res.status(500).json({ sucesso: false, mensagem: 'Erro ao limpar chamadas', erro: erro.message });
  }
});

// Adicionar/migrar tabela de pacientes para incluir data_criacao
// Função de migração para garantir que a coluna data_criacao exista na tabela pacientes
async function migrarTabelaPacientesAdicionarDataCriacao() {
  const db = await conectarBancoDeDados();
  // Adiciona a coluna se não existir (SQLite)
  if (DB_TYPE === 'sqlite') {
    await db.exec("ALTER TABLE pacientes ADD COLUMN data_criacao TEXT").catch(() => {});
  } else if (DB_TYPE === 'mysql') {
    await db.query("ALTER TABLE pacientes ADD COLUMN data_criacao DATE").catch(() => {});
  }
  if (DB_TYPE === 'sqlite') await db.close();
}
// Executa a migração ao iniciar
migrarTabelaPacientesAdicionarDataCriacao();

// Inicialização do servidor
// Sobe o servidor na porta configurada, inicializa o banco e agenda limpeza periódica de chamadas antigas
app.listen(CONFIG.PORTA, async () => {
  console.log(`Servidor rodando na porta ${CONFIG.PORTA}`);
  await inicializarBancoDeDados();
  // Limpeza periódica das chamadas antigas
  setInterval(async () => {
    try {
      const db = await conectarBancoDeDados();
      // Query de limpeza adaptada para cada banco
      if (DB_TYPE === 'sqlite') {
        await db.run("DELETE FROM chamadas WHERE datetime(horario) < datetime('now', '-24 hours')");
        await db.close();
      } else if (DB_TYPE === 'mysql') {
        await db.query("DELETE FROM chamadas WHERE horario < DATE_SUB(NOW(), INTERVAL 24 HOUR)");
      }
    } catch (erro) {
      console.error('Erro na limpeza de chamadas:', erro);
    }
  }, 12 * 60 * 60 * 1000);
});

module.exports = {
  app,
  conectarBancoDeDados
};
// Fim do arquivo: qualquer dúvida sobre como portar para MySQL, veja os comentários acima ou me pergunte!
