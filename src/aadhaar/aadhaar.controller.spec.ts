import { Test, TestingModule } from '@nestjs/testing';
import { AadhaarController } from './aadhaar.controller';

describe('AadhaarController', () => {
  let controller: AadhaarController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AadhaarController],
    }).compile();

    controller = module.get<AadhaarController>(AadhaarController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
