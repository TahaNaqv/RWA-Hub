const request = require('supertest');
const { ethers } = require('ethers');
const app = require('../src/server/server');

describe('Wallet sign-in', () => {
  const wallet = ethers.Wallet.createRandom();

  it('issues a JWT for a valid signature and rejects replay', async () => {
    const { body } = await request(app)
      .post('/api/auth/wallet/nonce')
      .send({ address: wallet.address })
      .expect(200);
    const signature = await wallet.signMessage(body.message);

    const res = await request(app)
      .post('/api/auth/wallet')
      .send({ address: wallet.address, signature })
      .expect(200);
    expect(res.body).toHaveProperty('token');

    const created = await request(app)
      .post('/api/assets')
      .set('Authorization', `Bearer ${res.body.token}`)
      .send({ title: 'Wallet asset', description: 'Created by a wallet user', price: { amount: 5 } })
      .expect(201);
    expect(created.body.ownerId).toBe(res.body.user.id);

    await request(app).post('/api/auth/wallet').send({ address: wallet.address, signature }).expect(401);
  });

  it('rejects a signature from a different key', async () => {
    const { body } = await request(app)
      .post('/api/auth/wallet/nonce')
      .send({ address: wallet.address })
      .expect(200);
    const other = ethers.Wallet.createRandom();
    const signature = await other.signMessage(body.message);
    await request(app).post('/api/auth/wallet').send({ address: wallet.address, signature }).expect(401);
  });
});
