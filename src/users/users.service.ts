import { Injectable, ConflictException } from '@nestjs/common'
import { InjectRepository } from '@nestjs/typeorm'
import { Repository } from 'typeorm'
import * as bcrypt from 'bcrypt'

import { CreateUserDto } from './dto/create-user.dto'
import { User } from './entities/user.entity'

@Injectable()
export class UsersService {
  // 1. Injeção de Dependência:
  // O NestJS nos entrega o "repositório" do User, que é o nosso portão de entrada
  // para fazer operações (salvar, buscar, etc.) na tabela 'user' do banco de dados.
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>
  ) {}

  // 2. Método 'create':
  // Esta função é o coração da nossa lógica de criação.
  async create(createUserDto: CreateUserDto): Promise<Omit<User, 'password'>> {
    // 1. Verifica se o email já existe no banco para evitar duplicados.
    const existingUser = await this.usersRepository.findOne({
      where: { email: createUserDto.email },
    })

    if (existingUser) {
      throw new ConflictException('Este endereço de email já está em uso.')
    }

    // 2. Gera o "hash" da senha para protegê-la.
    const salt = await bcrypt.genSalt()
    const hashedPassword = await bcrypt.hash(createUserDto.password, salt)

    // 3. Cria uma nova instância do usuário com a senha já protegida.
    const newUser = this.usersRepository.create({
      ...createUserDto,
      password: hashedPassword,
    })

    // 4. Salva o novo usuário no banco de dados.
    const savedUser = await this.usersRepository.save(newUser)

    // 5. A SOLUÇÃO:
    // Puxe a propriedade 'password' para uma constante separada (que não usaremos)
    // e coloque todo o "resto" das propriedades em um novo objeto chamado 'result'.
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...result } = savedUser

    // 6. Retorne o novo objeto 'result', que não contém a senha.
    return result
  }
}
