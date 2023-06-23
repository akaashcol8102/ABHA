import { Injectable } from '@nestjs/common';
import { HttpService } from '@nestjs/axios';
import { AxiosRequestConfig } from 'axios';
import * as crypto from 'crypto';
import * as readline from 'readline';
import * as jwt from 'jsonwebtoken';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';

@Injectable()
export class AadhaarService {
  private accessToken: string | null = null;
  private txnId: string | null = null;
  private readonly publicKeyUrl: string;

  constructor(
    private readonly httpService: HttpService,
    private readonly configService: ConfigService,
  ) {
    this.publicKeyUrl = this.configService.get<string>('PUBLIC_KEY_URL');
  }

  async getPublicKey(): Promise<string> {
    const publicKeyUrl = 'https://healthidsbx.abdm.gov.in/api/v2/auth/cert';
    try {
      const response = await this.httpService.get(publicKeyUrl).toPromise();
      console.log('Public Key Response:', response.data);
    //   const publicKey = response.data.publicKey;
      return response.data;
    } catch (error) {
      console.error('Error retrieving public key:', error);
    //   throw error;
    throw new Error(`Error retrieving public key: ${error.message}`);
    }
  }

  async encryptAadhaar(aadhaarNumber: string): Promise<string> {
    const response = await axios.get(this.publicKeyUrl);
    const publicKey = response.data;
    
    console.log('Public Key Response(Aadhaar):', publicKey);
    
    // publicKey = publicKey.replace("-----BEGIN PUBLIC KEY-----\n", '');
    // publicKey = publicKey.replace("\n-----END PUBLIC KEY-----", '');
    
    console.log('Public Key:', publicKey);
    if (typeof publicKey !== 'string') {
      throw new Error('Public key is not a string');
    }
    const buffer = Buffer.from(aadhaarNumber, 'utf8');
    const encrypted = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, buffer);
    return encrypted.toString('base64');
  }

  async encryptOtp(otp: string): Promise<string> {
    const response = await axios.get(this.publicKeyUrl);
    const publicKey = response.data;
    
    console.log('Public Key Response(OTP):', publicKey);
    if (typeof publicKey !== 'string') {
      throw new Error('Public key is not a string');
    }

    const buffer = Buffer.from(otp, 'utf8');
    const encrypted = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, buffer);
    return encrypted.toString('base64');
  }

  async makeAuthenticatedRequest(url: string, data: any): Promise<any> {
    console.log(data, "inge")
    await this.refreshTokenIfExpired();

    if (!this.accessToken) {
      throw new Error('Access token is missing or expired. Please authenticate first.');
    }

    const config: AxiosRequestConfig = {
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
      },
    };

    try {
      const response = await this.httpService.post(url, data, config).toPromise();
      console.log(response,"rspo")
      return response.data;
    } catch (error) {
         if (error.response && error.response.status === 401) {
      // Unauthorized error, refresh the token and retry the request
      await this.refreshToken();
      // Update the authorization header in the config
      config.headers.Authorization = `Bearer ${this.accessToken}`;
      // Retry the request with the new token
      // try {
      //   const response = await this.httpService.post(url, data, config).toPromise();
      //   return response.data;
      // } catch (error) {
      //   console.error('Error making authenticated request:', error.response.data);
      //   throw error;
      // }
    } else {
      console.error('Error making authenticated request:', error.response.data);
      throw error;
      }
    }
  }

  async refreshTokenIfExpired(): Promise<void> {
    if (!this.accessToken || this.isTokenExpired(this.accessToken)) {
      await this.refreshToken();
    }
  }

  async refreshToken(): Promise<void> {
    const authUrl = 'https://dev.abdm.gov.in/gateway/v0.5/sessions';
    const authData = {
      clientId: this.configService.get<string>('CLIENT_ID'),
      clientSecret: this.configService.get<string>('CLIENT_SECRET'),
      grantType: 'client_credentials',
    };
  
    try {
      const response = await this.httpService.post(authUrl, authData).toPromise();
      this.accessToken = response.data.accessToken;
      console.log('Token refreshed successfully:', this.accessToken);
    } catch (error) {
      console.error('Error refreshing token:', error.response.data);
      throw error;
    }
  }

  isTokenExpired(token: string): boolean {
    if (!token) {
      console.error('Token is missing or empty');
      return true;
    }

    const payload: any = jwt.decode(token);

    if (!payload) {
      return true;
    }

    if (!payload.exp) {
      console.warn('Token does not contain an expiration date');
      return false;
    }

    const currentDate = new Date();
    const expiryDate = new Date(payload.exp * 1000);

    return currentDate > expiryDate;
  }

  async authenticate(): Promise<void> {
    const authUrl = 'https://dev.abdm.gov.in/gateway/v0.5/sessions';
    const authData = {
      clientId: this.configService.get<string>('CLIENT_ID'),
      clientSecret: this.configService.get<string>('CLIENT_SECRET'),
      grantType: 'client_credentials',
    };

    try {
      const response = await this.httpService.post(authUrl, authData).toPromise();
      this.accessToken = response.data.accessToken;
      console.log('Authentication successful, token:', this.accessToken);
    } catch (error) {
      console.error('Error authenticating:', error.response.data);
      throw error;
    }
  }

  async encryptAndGenerateOTP(aadhaarNumber: string): Promise<void> {
    try {
      //   const publicKey = await this.getPublicKey();
      //   console.log('Public Key:', publicKey);
      console.log(`aadhaar`, aadhaarNumber);

      const encryptedAadhaar = await this.encryptAadhaar(aadhaarNumber);
      console.log('Encrypted Aadhaar:', encryptedAadhaar);

      const otpUrl = 'https://healthidsbx.abdm.gov.in/api/v2/registration/aadhaar/generateOtp';
      const otpData = {
        aadhaar: encryptedAadhaar,
      };
      const response = await this.makeAuthenticatedRequest(otpUrl, otpData);
      console.log('OTP Generation Response:', response);
      // this.txnId = response.txnId;
      return response;
    } catch (error) {
      console.error('Error encrypting Aadhaar number:', error);
      throw error;
    }
  }

  // ... the rest of your service code
  async verifyOtpAndGenerateMobileOtp(otp: string, txnId: string): Promise<any> {
    try {
      const encryptedOtpString = await this.encryptOtp(otp);
      console.log('Encrypted OTP:', encryptedOtpString);
  
      const authUrl = 'https://dev.abdm.gov.in/gateway/v0.5/sessions';
      const authData = {
          clientId: "SBX_002928",
          clientSecret: "5b24ab9e-2194-4f5f-aca3-fdb0a4872312",
          grantType: "client_credentials"
      };
  
      const authResponse = await this.httpService.post(authUrl, authData).toPromise();
      console.log('Auth Response:', authResponse.data);
      
      if (!authResponse.data || !authResponse.data.accessToken) {
          console.error('No access token in auth response:', authResponse);
          throw new Error('Failed to authenticate');
      }
  
      this.accessToken = authResponse.data.accessToken;
      console.log('Access token:', this.accessToken);
  
      const config: AxiosRequestConfig = {
          headers: {
              Authorization: `Bearer ${this.accessToken}`,
          },
      };
  
      const verifyOtpUrl = 'https://healthidsbx.abdm.gov.in/api/v2/registration/aadhaar/verifyOtp';
      const verifyOtpData = {
          otp: encryptedOtpString,
          txnId: txnId,
      };
  
      console.log('Sending OTP verification request to:', verifyOtpUrl, 'with data:', verifyOtpData, 'and headers:', config.headers);
  
      const response = await this.httpService.post(verifyOtpUrl, verifyOtpData, config).toPromise();
  
      console.log('OTP Verification Response:', response.data);
      return response.data;
  
    } catch (error) {
      console.error('Error verifying OTP:', error);
      
      if (error.response && error.response.data) {
          console.error('Server responded with:', error.response.data);
          console.error('Response Status:', error.response.status);
          console.error('Response Headers:', error.response.headers);
      }
      
      throw error;
    }
  }

  async generateMobileOtp(mobileNumber: string,txnId: string): Promise<any> {
    try {
      const mobileOtpUrl = 'https://healthidsbx.abdm.gov.in/api/v2/registration/aadhaar/checkAndGenerateMobileOTP';
      const mobileOtpData = {
        mobile: mobileNumber,
        txnId: txnId, // Use the internally stored txnId
      };
      const response = await this.makeAuthenticatedRequest(mobileOtpUrl, mobileOtpData);
      console.log('Mobile OTP Generation Response(txnId):', response);
 
      if (response.mobileLinked) {
        await this.createHealthIdByAadhaar(txnId);
      } else {
        const rl = readline.createInterface({
          input: process.stdin,
          output: process.stdout
        });
 
        rl.question('Please enter your OTP: ', (otp) => {
          rl.close();
          return this.verifyMobileOTP(otp, txnId);
        });
      }
    } catch (error) {
      console.error('Error generating txnId:', error);
      throw error;
    }
  }

  async createHealthIdByAadhaar(txnId: string): Promise<any> {
    try {
      const createHealthIdUrl = 'https://healthidsbx.abdm.gov.in/api/v2/registration/aadhaar/createHealthIdByAdhaar';
      const createHealthIdData = {
        consent: true,
        consentVersion: 'v1.0',
        txnId: txnId, // Use the internally stored txnId,
      };
      const response = await this.makeAuthenticatedRequest(createHealthIdUrl, createHealthIdData);
      console.log('Create Health ID Response:', response);
      return response;
    } catch (error) {
      console.error('Error creating health ID:', error);
      throw error;
    }
  }

  async verifyMobileOTP(otp: string, txnId: string): Promise<any> {
    try {
      const verifyMobileOtpUrl = 'https://healthidsbx.abdm.gov.in/api/v2/registration/aadhaar/verifyMobileOTP';
      const verifyMobileOtpData = {
        otp: otp,
        txnId: txnId, // Use the internally stored txnId
      };
      const response = await this.makeAuthenticatedRequest(verifyMobileOtpUrl, verifyMobileOtpData);
      console.log('Verify Mobile OTP Response:', response);
 
      // If the response from verifyMobileOTP is just the txnId, then proceed to create the health ID
      if (response === this.txnId) {
        const healthIdResponse = await this.createHealthIdByAadhaar(txnId);
        console.log('Create Health ID Response:', healthIdResponse);
        return healthIdResponse;
      } else {
        console.error('OTP verification failed. Health ID creation aborted.');
        return response;
      }
    } catch (error) {
      console.error('Error verifying mobile OTP:', error);
      throw error;
    }
  }
}

