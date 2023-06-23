import { Module } from '@nestjs/common';
import { AadhaarService } from './aadhaar.service';
import { AadhaarController } from './aadhaar.controller';
import { ConfigModule } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [HttpModule, ConfigModule], // Add HttpModule here
  providers: [AadhaarService],
  controllers: [AadhaarController],
})
export class AadhaarModule {}
