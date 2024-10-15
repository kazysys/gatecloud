const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const { Client, GatewayIntentBits } = require('discord.js'); // Importando discord.js

const app = express();
const PORT = process.env.PORT || 3000;

// Conexão ao MongoDB
mongoose.connect('mongodb+srv://Gate:Gate123@gate.tgf7v.mongodb.net/?retryWrites=true&w=majority&appName=Gate', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('Conectado ao MongoDB'))
  .catch(err => console.error('Erro de conexão:', err));

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // Para analisar dados de formulários
app.use(express.static('public')); // Serve arquivos estáticos da pasta public

// Configuração de sessão
app.use(session({
    secret: 'seu_segredo_aqui', // Troque por uma chave secreta
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false } // Defina como true se estiver usando HTTPS
}));

// Inicializa o Passport
app.use(passport.initialize());
app.use(passport.session());

// Serialização e deserialização de usuários
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

// Configuração da estratégia de login
passport.use(new LocalStrategy(
    { usernameField: 'email' },
    async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: 'Usuário não encontrado' });
            }
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return done(null, false, { message: 'Senha incorreta' });
            }
            return done(null, user);
        } catch (error) {
            return done(error);
        }
    }
));

// Modelo de Usuário
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },  // Adiciona 'required: true'
    email: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' },
    plan: { type: String, default: 'none' },
    machine: { 
        ip: String,
        user: String,
        password: String
    }
});

const User = mongoose.model('User', UserSchema);

// Função para verificar se o usuário é admin
function isAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        return next(); // O usuário é um administrador
    } else {
        return res.status(403).json({ message: 'Acesso negado' }); // Acesso negado
    }
}

// Rota para registro de usuário
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    // Verificar se os campos estão corretos
    console.log('Dados recebidos no registro:', { username, email, password });

    if (!username || !email || !password) {
        return res.status(400).json({ success: false, message: 'Preencha todos os campos obrigatórios' });
    }

    try {
        const existingUser = await User.findOne({ email });
        console.log('Usuário existente:', existingUser);
        if (existingUser) {
            return res.json({ success: false, message: 'Email já está registrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            username,
            email,
            password: hashedPassword
        });

        await newUser.save();
        console.log('Usuário registrado com sucesso:', newUser);
        return res.json({ success: true });
    } catch (error) {
        if (error.code === 11000) {
            const duplicateField = Object.keys(error.keyValue)[0];
            console.log('Erro de chave duplicada:', duplicateField);
            return res.status(400).json({ success: false, message: `${duplicateField} já está em uso` });
        }

        console.error('Erro ao registrar:', error);
        return res.status(500).json({ success: false, message: 'Erro ao tentar registrar' });
    }
});

// Rota para login
app.post('/login', passport.authenticate('local'), (req, res) => {
    res.json({ success: true, message: 'Login bem-sucedido!' });
});

// Middleware de autenticação
const isAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) { // Verifica se o usuário está autenticado
        return next(); // Usuário autenticado, prossiga
    }
    return res.status(403).json({ success: false, message: 'Acesso negado. Você precisa estar logado.' });
};

// Rota para o Dashboard (apenas usuários autenticados)
app.get('/dashboard', isAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id); // Obtém o usuário autenticado

        if (!user) {
            return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
        }

        // Retorna os dados do usuário e a máquina associada
        return res.json({
            success: true,
            user: {
                name: user.username,
                email: user.email,
                machine: user.machine, // Inclui a máquina associada
                plan: user.plan
            }
        });
    } catch (error) {
        console.error('Erro ao obter dados do dashboard:', error);
        return res.status(500).json({ success: false, message: 'Erro ao obter dados do dashboard' });
    }
});

// Rota para acessar admin.html
app.get('/admin', isAuthenticated, isAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Modelo de Máquina
const MachineSchema = new mongoose.Schema({
    name: String,
    type: String,
    ip: String,
    user: String,
    password: String
});

const Machine = mongoose.model('Machine', MachineSchema);

// Rota para adicionar máquina
app.post('/add-machine', async (req, res) => {
    const { name, type, ip, user, password } = req.body;

    try {
        const newMachine = new Machine({
            name,
            type,
            ip,
            user,
            password
        });

        await newMachine.save();
        return res.json({ success: true, message: 'Máquina adicionada com sucesso!' });
    } catch (error) {
        console.error('Erro ao adicionar máquina:', error);
        return res.status(500).json({ success: false, message: 'Erro ao adicionar máquina' });
    }
});

// Rota para associar máquina ao usuário
app.post('/associate-machine', async (req, res) => {
    const { userId, machineId } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
        }

        const machine = await Machine.findById(machineId);
        if (!machine) {
            return res.status(404).json({ success: false, message: 'Máquina não encontrada' });
        }

        user.machine = {
            ip: machine.ip,
            user: machine.user,
            password: machine.password
        };

        await user.save();

        return res.json({ success: true, message: 'Máquina associada com sucesso' });
    } catch (error) {
        console.error('Erro ao associar máquina:', error);
        return res.status(500).json({ success: false, message: 'Erro ao associar máquina' });
    }
});

// Modelo de Plano
const PlanSchema = new mongoose.Schema({
    name: String,
    price: Number
});

const Plan = mongoose.model('Plan', PlanSchema);

app.post('/addPlan', async (req, res) => {
    const { userId, planName, planPrice } = req.body;

    try {
        // Verifica se o usuário existe
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
        }

        // Adiciona o plano ao usuário
        user.plan = { name: planName, price: planPrice };
        
        // Busca uma máquina disponível
        const availableMachine = await Machine.findOne({ userId: null });
        if (!availableMachine) {
            return res.status(404).json({ success: false, message: 'Nenhuma máquina disponível.' });
        }

        // Associa a máquina ao usuário
        availableMachine.userId = user._id;
        await availableMachine.save();

        // Salva o usuário com o plano atualizado
        await user.save();

        return res.json({ success: true, message: 'Plano adicionado e máquina associada com sucesso.' });
    } catch (error) {
        console.error('Erro ao adicionar plano:', error);
        return res.status(500).json({ success: false, message: 'Erro interno do servidor.' });
    }
});


app.get('/getUsers', async (req, res) => {
    try {
        const users = await User.find({}, 'username _id'); // Certifique-se de obter os campos que quer retornar
        return res.json({ success: true, users });
    } catch (error) {
        console.error('Erro ao obter usuários:', error);
        return res.status(500).json({ success: false, message: 'Erro ao obter usuários.' });
    }
});



app.get('/getMachine', async (req, res) => {
    try {
        // Verifica se req.user está definido
        if (!req.user || !req.user.id) {
            return res.status(401).json({ success: false, message: 'Usuário não autenticado.' });
        }

        const userId = req.user.id; // Supondo que você tenha a informação do usuário
        const user = await User.findById(userId).populate('machine'); // Popula a máquina associada
     


        // Verifica se o usuário ou a máquina associada foram encontrados
        if (!user) {
            return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
        }
        if (!user.machine) {
            return res.json({ success: false, message: 'Usuário não tem máquina associada.' });
        }
        app.get('/getMachines', async (req, res) => {
            try {
                const machines = await Machine.find(); // Ajuste conforme seu modelo
                res.json({ success: true, machines });
            } catch (error) {
                console.error("Erro ao obter máquinas:", error);
                res.status(500).json({ success: false, message: 'Erro ao obter máquinas.' });
            }
        });
        

        res.json({ success: true, machine: user.machine });
    } catch (error) {
        console.error("Erro ao obter máquina:", error);
        res.status(500).json({ success: false, message: `Erro ao obter máquina associada: ${error.message}` });
    }
});


// Rota para o Webhook
app.post('/webhook', async (req, res) => {
    const data = req.body;
    console.log('Dados recebidos do webhook:', data);

    // Enviar uma mensagem para o canal do Discord usando o webhook
    const webhookUrl = 'https://discord.com/api/webhooks/1294026549506347139/h-hQbQm7UuskqOwyG4P1c_0mpTXGWmYEXsmd4DPz-FkVd3x6VBOts0xdiU4lETHvFov1'; 
    const { WebhookClient } = require('discord.js');
    const webhookClient = new WebhookClient({ url: webhookUrl });

    await webhookClient.send({
        content: `Recebido: ${JSON.stringify(data)}`, // Enviar os dados do webhook
    });

    res.status(200).send('Webhook recebido com sucesso');
});



app.get('/liberarPin', (req, res) => {
    // Lógica para liberar o PIN, talvez enviando uma resposta ou acionando um serviço
    console.log('Liberar PIN acionado!');
    res.json({ success: true, message: 'PIN liberado!' });
});

// Rota para obter uma máquina disponível
app.get('/getAvailableMachine', (req, res) => {
    Machine.findOne({ available: true }, (err, machine) => {
        if (err) {
            return res.json({ success: false, message: 'Erro ao buscar máquina disponível.' });
        }
        if (!machine) {
            return res.json({ success: false, message: 'Nenhuma máquina disponível.' });
        }
        res.json({ success: true, machine: machine });
    });
});



// Rotas para páginas HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/contact', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'contact.html'));
});

app.get('/ajuda-e-saiba-mais', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'ajuda-e-saiba-mais.html'));
});

app.get('/blog', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'blog.html'));
});

app.get('/maquinas', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'maquinas.html'));
});

app.get('/planos', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'planos.html'));
});

// Iniciar o servidor
app.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
