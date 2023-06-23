import { Test, TestingModule } from '@nestjs/testing';
import { AadhaarService } from './aadhaar.service';

describe('AadhaarService', () => {
  let service: AadhaarService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [AadhaarService],
    }).compile();

    service = module.get<AadhaarService>(AadhaarService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
