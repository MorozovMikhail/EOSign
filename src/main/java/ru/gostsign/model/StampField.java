package ru.gostsign.model;

import lombok.Data;

@Data
public class StampField {
    private String name;
    private float x;
    private float y;
    private float fontSize;
    private String color;
    
    public StampField(String name, float x, float y, float fontSize, String color) {
        this.name = name;
        this.x = x;
        this.y = y;
        this.fontSize = fontSize;
        this.color = color;
    }
} 