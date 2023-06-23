import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config'; // Import ConfigModule
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AadhaarModule } from './aadhaar/aadhaar.module';

@Module({
  imports: [
    AadhaarModule,
    ConfigModule.forRoot(), // Add ConfigModule.forRoot()
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
